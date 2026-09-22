// PM2 config — keeps server running forever on a VPS
// Usage: pm2 start ecosystem.config.js
module.exports = {
  apps: [{
    name:          'srtx-key-server',
    script:        'server.js',
    instances:     1,
    exec_mode:     'fork',
    watch:         false,
    max_memory_restart: '300M',   // restart if RAM exceeds 300MB
    restart_delay: 2000,          // wait 2s before restart
    max_restarts:  15,
    min_uptime:    '5s',
    env: {
      NODE_ENV: 'production',
    },
    error_file:  './logs/error.log',
    out_file:    './logs/out.log',
    log_date_format: 'YYYY-MM-DD HH:mm:ss',
  }],
};
