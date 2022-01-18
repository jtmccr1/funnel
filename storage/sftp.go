package storage

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	urllib "net/url"
	"os"
	pathlib "path"
	"path/filepath"
	"strings"

	"github.com/ohsu-comp-bio/funnel/config"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

//TODO needs context
//TODO how do we get funnel to call this?
//TODO does it work?
// SFTP provides read and write access to a sftp server URLs.
type SFTP struct {
	conf config.SFTPStorage // never needed
}

// NewFTP creates a new FTP instance.
func NewSFTP(conf config.SFTPStorage) (*SFTP, error) {
	return &SFTP{conf: conf}, nil
}

// Stat returns information about the object at the given storage URL.
func (b *SFTP) Stat(ctx context.Context, url string) (*Object, error) {
	client, err := sftpConnect(url, b.conf)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	return client.Stat(ctx, url)
}

// Get copies a file from a given URL to the host path.
func (b *SFTP) Get(ctx context.Context, url, path string) (*Object, error) {
	client, err := sftpConnect(url, b.conf)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	return client.Get(ctx, url, path)
}

// Put is not supported by FTP storage.
func (b *SFTP) Put(ctx context.Context, url string, hostPath string) (*Object, error) {
	client, err := sftpConnect(url, b.conf)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	return client.Put(ctx, url, hostPath)
}

// Join joins the given URL with the given subpath.
func (b *SFTP) Join(url, path string) (string, error) {
	return ftpJoin(url, path)
}

// List is not supported by FTP storage.
func (b *SFTP) List(ctx context.Context, url string) ([]*Object, error) {
	client, err := sftpConnect(url, b.conf)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	return client.List(ctx, url)
}

// UnsupportedOperations describes which operations (Get, Put, etc) are not
// supported for the given URL.
func (b *SFTP) UnsupportedOperations(url string) UnsupportedOperations {
	if err := b.supportsPrefix(url); err != nil {
		return AllUnsupported(err)
	}
	return AllSupported()
}

func (b *SFTP) supportsPrefix(url string) error {
	if !strings.HasPrefix(url, "sftp://") {
		return &ErrUnsupportedProtocol{"stpStorage"}
	}
	return nil
}

// sftpclient gives access to the sftp client and ssh connection.
type sftpclient struct {
	connection *ssh.Client
	client     *sftp.Client
}

func sftpConnect(url string, conf config.SFTPStorage) (*sftpclient, error) {

	// A public key may be used to authenticate against the remote
	// server by using an unencrypted PEM-encoded private key file.
	//
	// If you have an encrypted private key, the crypto/x509 package
	// can be used to decrypt it.
	keyFile := conf.Key
	if keyFile == "" {
		keyFile = os.Getenv("HOME") + "/.ssh/id_rsa"
	}

	key, err := ioutil.ReadFile(keyFile)

	if err != nil {
		fmt.Errorf("unable to read private key: %v", err)
	}

	// Create the Signer for this private key.
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		fmt.Errorf("unable to parse private key: %v", err)
	}
	u, err := urllib.Parse(url)
	if err != nil {
		return nil, fmt.Errorf("stpStorage: parsing URL: %s", err)
	}

	host := u.Host + ":22"

	hostKey := getHostKey(u.Host)
	println(hostKey)
	println(host)
	config := ssh.ClientConfig{
		User: conf.User,
		Auth: []ssh.AuthMethod{
			// Use the PublicKeys method for remote authentication.
			ssh.PublicKeys(signer),
		},
		// HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		HostKeyCallback: ssh.FixedHostKey(hostKey),
	}

	// Connect to the remote server and perform the SSH handshake.
	connection, err := ssh.Dial("tcp", host, &config)
	if err != nil {
		return nil, fmt.Errorf("stpStorage: connecting to server: %v", err)
	}
	// defer client.Close()

	client, err := sftp.NewClient(connection)
	if err != nil {
		log.Fatal(err)
	}
	// defer client.Close()

	return &sftpclient{connection, client}, nil
}

func (b *sftpclient) Close() {
	b.connection.Close()
	b.client.Close()
}

// Stat returns information about the object at the given storage URL.
func (b *sftpclient) Stat(ctx context.Context, url string) (*Object, error) {
	u, err := urllib.Parse(url)
	if err != nil {
		return nil, fmt.Errorf("sftpStorage: parsing URL: %s", err)
	}

	resp, err := b.client.Stat(u.Path)
	if err != nil {
		return nil, fmt.Errorf("stpStorage: listing path: %q %v", u.Path, err)
	}

	return &Object{
		URL:          url,
		Name:         strings.TrimPrefix(u.Path, "/"),
		LastModified: resp.ModTime(),
		Size:         resp.Size(),
	}, nil
}

// Get copies a file from a given URL to the host path.
func (b *sftpclient) Get(ctx context.Context, url, path string) (*Object, error) {
	obj, err := b.Stat(ctx, url)
	if err != nil {
		return nil, err
	}
	remotePath := "/" + obj.Name

	src, err := b.client.OpenFile(remotePath, (os.O_RDONLY))
	if err != nil {

		return nil, fmt.Errorf("stpStorage: Unable to open remote file %s: %v", remotePath, err)
	}
	defer src.Close()

	dest, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("stpStorage: creating host file: %s", err)
	}

	_, copyErr := io.Copy(dest, src)
	closeErr := dest.Close()

	if copyErr != nil {
		return nil, fmt.Errorf("stpStorage: copying file: %s", copyErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("stpStorage: closing file: %s", closeErr)
	}

	return obj, err
}

func (b *sftpclient) Put(ctx context.Context, url string, hostPath string) (*Object, error) {

	u, err := urllib.Parse(url)
	if err != nil {
		return nil, fmt.Errorf("stpStorage: parsing URL: %s", err)
	}

	reader, err := os.Open(hostPath)
	if err != nil {
		return nil, fmt.Errorf("stpStorage: opening host file for %q: %v", url, err)
	}
	defer reader.Close()

	dirpath, _ := pathlib.Split(u.Path)

	err = b.client.MkdirAll(dirpath)

	if err != nil {
		return nil, fmt.Errorf("sftpclient: making directory to %q: %v", dirpath, err)
	}

	dstFile, err := b.client.OpenFile(u.Path, (os.O_WRONLY | os.O_CREATE | os.O_TRUNC))
	if err != nil {
		return nil, fmt.Errorf("Unable to open remote file: %v\n", err)
	}
	defer dstFile.Close()
	_, err = io.Copy(dstFile, reader)

	if err != nil {
		return nil, fmt.Errorf("sftpclient: uploading file for %q: %v", url, err)
	}

	return b.Stat(ctx, url)
}

func (b *sftpclient) List(ctx context.Context, url string) ([]*Object, error) {
	u, err := urllib.Parse(url)
	if err != nil {
		return nil, fmt.Errorf("sftpclient: parsing URL: %s", err)
	}

	files, err := b.client.ReadDir(u.Path)
	if err != nil {
		return nil, fmt.Errorf("sftpclient: listing path: %q %v", u.Path, err)
	}

	objects := make([]*Object, 0)

	for _, f := range files {

		stats, err := b.Stat(ctx, f.Name())
		if err != nil {
			return nil, fmt.Errorf("sftpclient: listing path: %q %v", u.Path, err)
		}
		objects = append(objects, stats)

	}

	// Special case where the user called List on a regular file.

	return objects, nil
}

// sftpJoin joins the given URL with the given subpath.
func sftpJoin(url, path string) (string, error) {
	return strings.TrimSuffix(url, "/") + "/" + path, nil
}

//https://sftptogo.com/blog/go-sftp/
func getHostKey(host string) ssh.PublicKey {
	// parse OpenSSH known_hosts file
	// ssh or use ssh-keyscan to get initial key
	file, err := os.Open(filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to read known_hosts file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var hostKey ssh.PublicKey
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) != 3 {
			continue
		}
		if strings.Contains(fields[0], host) {
			var err error
			hostKey, _, _, _, err = ssh.ParseAuthorizedKey(scanner.Bytes())
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error parsing %q: %v\n", fields[2], err)
				os.Exit(1)
			}
			break
		}
	}

	if hostKey == nil {
		fmt.Fprintf(os.Stderr, "No hostkey found for %s", host)
		os.Exit(1)
	}

	return hostKey
}
