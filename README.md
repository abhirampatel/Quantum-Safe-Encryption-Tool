# Encrypted File System

A secure file storage application with quantum-safe encryption.

## Local Development

1. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Run the application:
   ```
   python app.py
   ```

## AWS Deployment

This application is configured for deployment to AWS Elastic Beanstalk.

### Prerequisites

1. Install AWS CLI and EB CLI:
   ```
   pip install awscli awsebcli
   ```

2. Configure AWS credentials:
   ```
   aws configure
   ```

### Deployment Steps

1. Initialize your EB application:
   ```
   eb init -p python-3.11 your-application-name
   ```

2. Create an environment:
   ```
   eb create your-environment-name
   ```

3. Deploy updates:
   ```
   eb deploy
   ```

4. Open your application in a browser:
   ```
   eb open
   ```

### Security Configuration

For production deployment, you should:

1. Create an IAM role with S3 access permissions for your Elastic Beanstalk environment
2. Set a secure SECRET_KEY in the environment variables
3. Remove hardcoded AWS credentials from the code

### Environment Variables

The following environment variables can be configured:

- `FLASK_ENV`: Set to 'production' for production deployment
- `SECRET_KEY`: A secure secret key for session management
- `S3_BUCKET_NAME`: The name of your S3 bucket
- `S3_ACCESS_KEY`: Your AWS access key (use IAM roles instead in production)
- `S3_SECRET_KEY`: Your AWS secret key (use IAM roles instead in production)
- `S3_REGION`: The AWS region for your S3 bucket
