/**
 * Cross-platform backend setup script
 */

const { setupBackend } = require('./setup.js');

console.log('🔧 Setting up backend...\n');
setupBackend().then(() => {
  console.log('✅ Backend setup complete!');
}).catch((error) => {
  console.error('❌ Backend setup failed:', error);
  process.exit(1);
});

