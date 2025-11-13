/**
 * Cross-platform backend startup script
 */

const { spawn } = require('child_process');
const path = require('path');
const os = require('os');

const platform = os.platform();
const isWindows = platform === 'win32';

console.log('🚀 Starting Safe T Net Backend...\n');

const backendPath = path.join(__dirname, 'SafeTNet');
const venvPath = path.join(backendPath, 'venv');

// Determine the command based on platform
let command;
let args;

if (isWindows) {
  // Windows: use venv\Scripts\python.exe
  command = path.join(venvPath, 'Scripts', 'python.exe');
  args = ['manage.py', 'runserver', '8000'];
} else {
  // Linux/Mac: use venv/bin/python
  command = path.join(venvPath, 'bin', 'python');
  args = ['manage.py', 'runserver', '8000'];
}

console.log(`📦 Using Python: ${command}\n`);

const backendProcess = spawn(command, args, {
  cwd: backendPath,
  stdio: 'inherit',
  shell: false
});

backendProcess.on('error', (error) => {
  console.error('❌ Error starting backend:', error);
  
  // If venv doesn't exist, run setup
  console.log('\n⚠️  Virtual environment not found. Running setup...\n');
  const { exec } = require('child_process');
  
  exec('node setup.js', (error, stdout, stderr) => {
    if (error) {
      console.error('Setup failed:', error);
      process.exit(1);
    }
  });
});

backendProcess.on('exit', (code) => {
  if (code !== 0 && code !== null) {
    console.error(`Backend process exited with code ${code}`);
  }
});

