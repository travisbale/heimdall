pipeline {
  agent {
    docker {
      image 'python:3.8-alpine'
      args '-p 5000:5000'
    }

  }
  stages {
    stage('Install') {
      steps {
        sh 'echo Installing...'
      }
    }
    stage('Test') {
      steps {
        sh 'echo Testing...'
      }
    }
    stage('Deploy') {
      steps {
        sh 'echo Deploying...'
      }
    }
  }
}
