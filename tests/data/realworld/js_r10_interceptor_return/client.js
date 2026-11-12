const axios = require('axios');
// FP: interceptor callbacks registered with .use() become "entry points"; returning the param is an "HTTP response"
axios.interceptors.request.use((config) => {
  config.headers['X-Trace'] = '1';
  return config;
});
