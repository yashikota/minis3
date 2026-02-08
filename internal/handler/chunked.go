package handler

import (
	"bytes"
	"io"
	"strconv"
	"strings"
)

// decodeAWSChunkedBody decodes AWS chunked transfer encoding from the request body.
// AWS chunked format: <chunk-size in hex>;chunk-signature=<signature>\r\n<data>\r\n...0;chunk-signature=<sig>\r\n\r\n
func decodeAWSChunkedBody(body io.Reader) ([]byte, error) {
	var result bytes.Buffer
	reader := &chunkedReader{r: body}

	for {
		chunk, err := reader.readChunk()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		if len(chunk) == 0 {
			break
		}
		result.Write(chunk)
	}

	return result.Bytes(), nil
}

type chunkedReader struct {
	r io.Reader
}

func (cr *chunkedReader) readChunk() ([]byte, error) {
	// Read until we find \r\n which marks end of chunk header
	line, err := cr.readLine()
	if err != nil {
		return nil, err
	}

	// Parse chunk size (format: <hex-size>;chunk-signature=<sig>)
	// or just <hex-size> for simpler cases
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, io.EOF
	}

	// Extract size part (before semicolon if present)
	sizePart := line
	if idx := strings.Index(line, ";"); idx != -1 {
		sizePart = line[:idx]
	}

	size, err := strconv.ParseInt(sizePart, 16, 64)
	if err != nil {
		return nil, err
	}

	if size == 0 {
		// Read trailing headers until empty line
		for {
			trailer, err := cr.readLine()
			if err != nil {
				return nil, nil
			}
			if strings.TrimSpace(trailer) == "" {
				break
			}
		}
		return nil, io.EOF
	}

	// Read chunk data
	data := make([]byte, size)
	_, err = io.ReadFull(cr.r, data)
	if err != nil {
		return nil, err
	}

	// Read trailing \r\n
	_, _ = cr.readLine()

	return data, nil
}

func (cr *chunkedReader) readLine() (string, error) {
	var line bytes.Buffer
	buf := make([]byte, 1)

	for {
		n, err := cr.r.Read(buf)
		if err != nil {
			if err == io.EOF && line.Len() > 0 {
				return line.String(), nil
			}
			return "", err
		}
		if n == 0 {
			continue
		}

		if buf[0] == '\n' {
			result := line.String()
			// Remove trailing \r if present
			result = strings.TrimSuffix(result, "\r")
			return result, nil
		}
		line.WriteByte(buf[0])
	}
}

// isAWSChunkedEncoding checks if the request uses AWS chunked encoding.
func isAWSChunkedEncoding(contentEncoding string) bool {
	return strings.Contains(contentEncoding, "aws-chunked")
}
