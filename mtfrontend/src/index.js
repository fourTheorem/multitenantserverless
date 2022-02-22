import React from 'react';
import ReactDOM from 'react-dom';
import './index.css';
import App from './App';
import reportWebVitals from './reportWebVitals';

import Amplify from '@aws-amplify/core'
import { Auth } from '@aws-amplify/auth'

Amplify.configure({
  Auth: {
    userPoolId: process.env.REACT_APP_USER_POOL_ID,
    userPoolWebClientId: process.env.REACT_APP_USER_POOL_CLIENT_ID,
    identityPoolId: process.env.REACT_APP_IDENTITY_POOL_ID,
    region: process.env.REACT_APP_AWS_REGION,
    // mandatorySignIn?: boolean;
    // cookieStorage?: ICookieStorageData;
    // oauth?: OAuthOpts;
    // refreshHandlers?: object;
    // storage?: ICognitoStorage;
    // authenticationFlowType?: string;
    // identityPoolRegion?: string;
    // clientMetadata?: any;
    // endpoint?: string;
  },
  API: {
    endpoints: [
      {
        name: 'things_pool',
        endpoint: process.env.REACT_APP_ENDPOINT_URL, // (required) -API Gateway URL + environment
        region: process.env.REACT_APP_AWS_REGION, // (required) - API Gateway region
        custom_header: async () => { 
          const token = (await Auth.currentSession()).getIdToken().getJwtToken()
          return { Authorization: `Bearer ${token}` }
        }
      },
      {
        name: 'things_iam',
        endpoint: process.env.REACT_APP_ENDPOINT_URL, // (required) -API Gateway URL + environment
        region: process.env.REACT_APP_AWS_REGION, // (required) - API Gateway region
      }
    ]
  }
})

ReactDOM.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
  document.getElementById('root')
);

// If you want to start measuring performance in your app, pass a function
// to log results (for example: reportWebVitals(console.log))
// or send to an analytics endpoint. Learn more: https://bit.ly/CRA-vitals
reportWebVitals();
