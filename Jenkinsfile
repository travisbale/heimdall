pipeline {
  agent any

  environment {
    IMAGE_TAG = "${env.BRANCH_NAME == 'master' ? '0.1' : '0.1-rc'}"
    ENV_FILE = "${env.BRANCH_NAME == 'master' ? 'prod.env' : 'staging.env'}"
    CONTAINER_NAME = "${env.BRANCH_NAME == 'master' ? 'heimdall' : 'heimdall-rc'}"
  }

  stages {
    stage('Build') {
      steps {
        sh 'mkdir -p keys'
        sh 'cp /home/keys/heimdall.* keys'
        sh 'docker build -t heimdall:$IMAGE_TAG .'
      }
    }

    stage('Test') {
      steps {
        sh 'docker run --rm --entrypoint python heimdall:$IMAGE_TAG -m pytest'
      }
    }

    stage('Deploy') {
      steps {
        // Don't fail the build if the container does not exist
        sh 'docker stop $CONTAINER_NAME || true'
        sh '''
          docker run -d --rm \
            --name $CONTAINER_NAME \
            --env-file /home/env/heimdall/$ENV_FILE \
            --network=ec2-user_default \
            heimdall:$IMAGE_TAG
        '''
      }
    }
    stage('Test Deployment') {
      environment {
        API_KEY = credentials('pm-apikey')
        COLLECTION_ID = credentials('pm-heimdall-collection-id')
        ENVIRONMENT_ID = credentials('pm-heimdall-prod-env-id')
        USER_EMAIL = credentials('pm-heimdall-user-email')
        USER_PASSWORD = credentials('pm-heimdall-user-password')
      }
      steps {
        sh '''
          docker run --rm -t postman/newman \
            run https://api.getpostman.com/collections/$COLLECTION_ID?apikey=$API_KEY \
            -e https://api.getpostman.com/environments/$ENVIRONMENT_ID?apikey=$API_KEY \
            --env-var user_email=$USER_EMAIL \
            --env-var user_password=$USER_PASSWORD \
            -n 3
        '''
      }
    }
  }
}
