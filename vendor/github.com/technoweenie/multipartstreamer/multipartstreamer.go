/*
Package multipartstreamer helps you encode large files in MIME multipart format
without reading the entire content into memory.  It uses io.MultiReader to
combine an inner multipart.Reader with a file handle.
*/
package multipartstreamer

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
)

type MultipartStreamer struct {
	ContentType   string
	bodyBuffer    *bytes.Buffer
	bodyWriter    *multipart.Writer
	closeBuffer   *bytes.Buffer
	reader        io.Reader
	contentLength int64
}

// New initializes a new MultipartStreamer.
func New() (m *MultipartStreamer) {
	m = &MultipartStreamer{bodyBuffer: new(bytes.Buffer)}

	m.bodyWriter = multipart.NewWriter(m.bodyBuffer)
	boundary := m.bodyWriter.Boundary()
	m.ContentType = "multipart/form-data; boundary=" + boundary

	closeBoundary := fmt.Sprintf("\r\n--%s--\r\n", boundary)
	m.closeBuffer = bytes.NewBufferString(closeBoundary)

	return
}

// WriteFields writes multiple form fields to the multipart.Writer.
func (m *MultipartStreamer) WriteFields(fields map[string]string) error {
	var err error

	for key, value := range fields {
		err = m.bodyWriter.WriteField(key, value)
		if err != nil {
			return err
		}
	}

	return nil
}

// WriteReader adds an io.Reader to get the content of a file.  The reader is
// not accessed until the multipart.Reader is copied to some output writer.
func (m *MultipartStreamer) WriteReader(key, filename string, size int64, reader io.Reader) (err error) {
	m.reader = reader
	m.contentLength = size

	_, err = m.bodyWriter.CreateFormFile(key, filename)
	return
}

// WriteFile is a shortcut for adding a local file as an io.Reader.
func (m *MultipartStreamer) WriteFile(key, filename string) error {
	fh, err := os.Open(filename)
	if err != nil {
		return err
	}

	stat, err := fh.Stat()
	if err != nil {
		return err
	}

	return m.WriteReader(key, filepath.Base(filename), stat.Size(), fh)
}

// SetupRequest sets up the http.Request body, and some crucial HTTP headers.
func (m *MultipartStreamer) SetupRequest(req *http.Request) {
	req.Body = m.GetReader()
	req.Header.Add("Content-Type", m.ContentType)
	req.ContentLength = m.Len()
}

func (m *MultipartStreamer) Boundary() string {
	return m.bodyWriter.Boundary()
}

// Len calculates the byte size of the multipart content.
func (m *MultipartStreamer) Len() int64 {
	return m.contentLength + int64(m.bodyBuffer.Len()) + int64(m.closeBuffer.Len())
}

// GetReader gets an io.ReadCloser for passing to an http.Request.
func (m *MultipartStreamer) GetReader() io.ReadCloser {
	reader := io.MultiReader(m.bodyBuffer, m.reader, m.closeBuffer)
	return ioutil.NopCloser(reader)
}
