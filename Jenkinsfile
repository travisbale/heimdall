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
          docker run -d --rm -p 5000:5000 \
            --name heimdall-rc \
            --env-file /home/env/heimdall.env \
            --network=ec2-user_default \
            heimdall:0.1-rc1
        '''
      }
    }
  }
}
