pipeline {
  agent any
  stages {
    stage('Build') {
      steps {
        sh 'mkdir -p keys'
        sh 'cp /home/keys/heimdall.* keys'
        sh 'docker build -t heimdall:0.1-rc1 .'
      }
    }
    stage('Test') {
      steps {
        sh 'docker run --rm --entrypoint python heimdall:0.1-rc1 -m pytest'
      }
    }
    stage('Deploy') {
      steps {
        // Don't fail the build if the container does not exist
        sh 'docker stop heimdall-rc || true'
        sh '''
          docker run -d --rm \
            --name heimdall-rc \
            --env-file /home/env/heimdall/staging.env \
            --network=ec2-user_default \
            heimdall:0.1-rc1
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
