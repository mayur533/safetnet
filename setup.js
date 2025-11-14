/**
 * Cross-platform setup script for Safe T Net
 * Works on Windows, Mac, and Linux
 */

const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

const platform = os.platform();
const isWindows = platform === 'win32';

console.log('🚀 Safe T Net - Setting up the development environment...\n');

// Setup Frontend
function setupFrontend() {
  return new Promise((resolve, reject) => {
    console.log('📦 Installing frontend dependencies...');
    const frontendPath = path.join(__dirname, 'safe-fleet-admin');
    
    exec('npm install', { cwd: frontendPath }, (error, stdout, stderr) => {
      if (error) {
        console.error(`Frontend setup error: ${error}`);
        reject(error);
      } else {
        console.log('✅ Frontend dependencies installed\n');
        resolve();
      }
    });
  });
}

// Setup Backend
function setupBackend() {
  return new Promise((resolve, reject) => {
    console.log('🐍 Setting up Python virtual environment...');
    const backendPath = __dirname;
    const backendPath = __dirname;
    const venvPath = path.join(backendPath, 'venv');
    
    // Check if venv already exists
    if (fs.existsSync(venvPath)) {
      console.log('✅ Virtual environment already exists');
      // Still install/upgrade dependencies
      installBackendDependencies(backendPath, resolve, reject);
    } else {
      // Create venv based on platform
      const pythonCmd = isWindows ? 'python' : 'python3';
      const venvCmd = isWindows 
        ? `${pythonCmd} -m venv venv`
        : `${pythonCmd} -m venv venv`;
      
      exec(venvCmd, { cwd: backendPath }, (error, stdout, stderr) => {
        if (error) {
          console.error(`Error creating virtual environment: ${error}`);
          reject(error);
          return;
        }
        console.log('✅ Virtual environment created');
        installBackendDependencies(backendPath, resolve, reject);
      });
    }
  });
}

function installBackendDependencies(backendPath, resolve, reject) {
  console.log('📦 Installing Python dependencies...');
  
  const pipPath = isWindows 
    ? path.join(backendPath, 'venv', 'Scripts', 'pip.exe')
    : path.join(backendPath, 'venv', 'bin', 'pip');
  
  // Upgrade pip
  exec(`"${pipPath}" install --upgrade pip`, { cwd: backendPath }, (error, stdout, stderr) => {
    if (error) {
      console.error(`Error upgrading pip: ${error}`);
    }
    
    // Install requirements
    exec(`"${pipPath}" install -r requirements.txt`, { cwd: backendPath }, (error, stdout, stderr) => {
      if (error) {
        console.error(`Error installing requirements: ${error}`);
        reject(error);
      } else {
        console.log('✅ Python dependencies installed\n');
        console.log('✅ Setup complete!\n');
        console.log('To start the application, run:');
        console.log('  npm start\n');
        resolve();
      }
    });
  });
}

// Run setup
async function main() {
  try {
    await setupFrontend();
    await setupBackend();
    console.log('🎉 All set! Ready to develop.');
  } catch (error) {
    console.error('❌ Setup failed:', error);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = { setupFrontend, setupBackend };

