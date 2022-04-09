package main

import (
	"os"
	"path/filepath"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

func downloadFromS3(awsSession *session.Session) error {
	folder := "/tmp/"
	filename := "sample"
	bucket := "malzoo-serverless-v1-231446340191-malware"

	// Create an instance of the S3 Downloader
	s3Downloader := s3manager.NewDownloader(awsSession)

	// Create a new temporary file
	tempFile, err := os.Create(filepath.Join(folder, filename))
	if err != nil {
		return err
	}

	// Prepare the download
	objectInput := &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(filename),
	}

	// Download the file to disk
	_, err = s3Downloader.Download(tempFile, objectInput)
	if err != nil {
		os.Remove(filepath.Join(folder, filename))
		return err
	}

	return nil
}

func uploadToS3() string {
	return "None"
}

func getFromDynamo() string {
	return "None"
}

func storeInDynamo() string {
	return "None"
}
