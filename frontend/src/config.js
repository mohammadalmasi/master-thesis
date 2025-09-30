const config = {
  development: {
    API_BASE_URL: 'http://localhost:5001',
  },
  production: {
    API_BASE_URL: 'https://api-dot-sql-scanner-thesis.de.r.appspot.com',
  },
};

const environment = process.env.NODE_ENV || 'development';

export default config[environment]; 