import * as React from 'react';
import Avatar from '@mui/material/Avatar';
import Button from '@mui/material/Button';
import TextField from '@mui/material/TextField';
import Grid from '@mui/material/Grid';
import Box from '@mui/material/Box';
import LockOutlinedIcon from '@mui/icons-material/LockOutlined';

import { Auth } from '@aws-amplify/auth'
import { API } from '@aws-amplify/api'
import { STS } from '@aws-sdk/client-sts'

class Login extends React.Component {

  constructor(props) {
    super()
    this.state = {}
    this.handleSubmit = this.handleSubmit.bind(this)
    this.handleDebug = this.handleDebug.bind(this)
    this.handleGetWithPool = this.handleGetWithPool.bind(this)
    this.handleGetWithIAM = this.handleGetWithIAM.bind(this)
    this.handleGetWithCustomAuth = this.handleGetWithCustomAuth.bind(this)
    this.handleUserGroupUpdate = this.handleUserGroupUpdate.bind(this)
    this.handleLogOut = this.handleLogOut.bind(this)
  }

  async handleDebug () {
    let user, credentials, session
    try {
      session = await Auth.currentSession()
    } catch(e) {}
    try {
      user = await Auth.currentAuthenticatedUser()
      credentials = await Auth.currentCredentials() 
    } catch(e) {}
    let iamIdentity = {}
    if (credentials) {
      const { accessKeyId, sessionToken, secretAccessKey, identityId } = credentials
      iamIdentity.identityId = identityId
      const sts = new STS({ credentials: { accessKeyId, sessionToken, secretAccessKey }, region: 'eu-west-1' })
      const callerIdentity = await sts.getCallerIdentity()
      iamIdentity.callerIdentity = callerIdentity
    }
    console.log({ session, user, credentials, iamIdentity })
    this.setState({ session, user, credentials, iamIdentity })
  }

  async handleLogOut() {
    const response = await Auth.signOut()
    console.log('Log out response', { response })
    await this.handleDebug()
  }

  async handleGetWithPool () {
    const response = await API.get('things_pool', '/thing_pool')
    console.log('API response with user pool authorizer', { response })
  }

  async handleGetWithIAM () {
    const response = await API.get('things_iam', '/thing_iam')
    console.log('API response with AWS_IAM authorizer', { response })
  }

  async handleGetWithCustomAuth () {
    const response = await API.get('things_pool', '/thing_custom')
    console.log('API response with custom auth', { response })
  }

  async handleUserGroupUpdate(event) {
    const data = new FormData(event.currentTarget.parentElement);
    const email = data.get('email');
    const org = data.get('org');
    const ou = data.get('ou');
    const group = data.get('group');

    const response = await API.put('things_pool', '/user-group', {
      body: { email, org, ou, group}
    })
    console.log('User/Group update response', { response })
  }

  async handleSubmit (event) {
    event.preventDefault();
    const submitter = event.nativeEvent.submitter.name
    const data = new FormData(event.currentTarget);
    const email = data.get('email');
    const password = data.get('password');
    const org = data.get('org');
    const ou = data.get('ou');
    const attributes = {}
    if (org) attributes['custom:org'] = org
    if (ou) attributes['custom:ou'] = ou

    try {
      switch (submitter) {
        case 'logIn':
          const signInResult = await Auth.signIn(email, password)
          console.log(signInResult)
          await this.handleDebug()
          break;
        case 'signUp':
          const signUpResult = await Auth.signUp({
            username: email,
            password,
            attributes
          })
          console.log(signUpResult)
          this.setState({ signUpResult })
          break;
        default:
          console.log('Unknown submitter:', submitter)
      }
    } catch (error) {
      console.error({ error })
      this.setState({ failed: true })
    }
  };

  render(props) {
    const idPayload = ((this.state.session || {}).idToken || {}).payload || {}
    const { email, sub: username, 'custom:ou': ou, 'custom:org': org, 'cognito:groups': groups } = idPayload
    // {
    //   "identityId": "eu-west-1:56b9cc73-2095-4bee-adfa-5a812ffa5bf5",
    //   "callerIdentity": {
    //     "$metadata": {
    //       "httpStatusCode": 200,
    //       "requestId": "f3747bb8-d86f-44fb-9d2f-47851e1b8435",
    //       "attempts": 1,
    //       "totalRetryDelay": 0
    //     },
    //     "UserId": "AROA5TWTPH6BZBIFCVKOB:CognitoIdentityCredentials",
    //     "Account": "935672627075",
    //     "Arn": "arn:aws:sts::935672627075:assumed-role/multitenantserverless-dev-mtAuthenticatedIdentityP-1KPE0CVHQ3ZF8/CognitoIdentityCredentials"
    //   }
    // }
    const { identityId, callerIdentity } = this.state.iamIdentity || {}
    const { Arn: roleArn } = callerIdentity || {}
    let iamStr = identityId ? `Id: ${identityId} Role: ${roleArn}` : ''
    return (
      <Box
        sx={{
          marginTop: 8,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
        }}
      >
        <Avatar sx={{ m: 1, bgcolor: 'secondary.main' }}>
          <LockOutlinedIcon />
        </Avatar>
        <Box component="form" noValidate onSubmit={this.handleSubmit} sx={{ mt: 1 }}>
          <Grid container spacing={2}>
            <Grid item xs={12}>
              <div>
              <b>User Pool idToken</b>: {email} {username} {ou} {org} {groups}
              </div>
              <div>
              <b>IAM</b>: {iamStr} 
              </div>
            </Grid>
            <Grid item xs={12}>
              <TextField
                autoComplete="given-name"
                name="name"
                required
                fullWidth
                id="name"
                label="Name"
                autoFocus
              />
            </Grid>
            <Grid item xs={12}>
              <TextField
                required
                fullWidth
                id="email"
                label="Email Address"
                name="email"
                autoComplete="email"
              />
            </Grid>
            <Grid item xs={12}>
              <TextField
                required
                fullWidth
                name="password"
                label="Password"
                type="password"
                id="password"
                autoComplete="new-password"
              />
            </Grid>
            <Grid item xs={12} sm={6}>
              <TextField
                required
                fullWidth
                id="org"
                label="Org"
                name="org"
              />
            </Grid>
            <Grid item xs={12} sm={6}>
              <TextField
                required
                fullWidth
                id="ou"
                label="OU"
                name="ou"
              />
            </Grid>
            <Grid item xs={12}>
              <TextField
                required
                fullWidth
                id="group"
                label="Group"
                name="group"
              />
            </Grid>
          </Grid>
          <Button
            name="signUp"
            type="submit"
            fullWidth
            variant="contained"
            sx={{ mt: 1, mb: 1 }}
          >
            Sign Up
          </Button>
          <Button
            name="logIn"
            type="submit"
            fullWidth
            variant="contained"
            sx={{ mt: 1, mb: 1 }}
          >
            Log In
          </Button>
          <Button
            fullWidth
            variant="contained"
            onClick={this.handleDebug}
            sx={{ mt: 1, mb: 1 }}
          >
            Debug
          </Button>
          <Button
            fullWidth
            variant="contained"
            onClick={this.handleGetWithPool}
            sx={{ mt: 1, mb: 1 }}
          >
            GET with User Pool Token
          </Button>
          <Button
            fullWidth
            variant="contained"
            onClick={this.handleGetWithIAM}
            sx={{ mt: 1, mb: 1 }}
          >
            GET with IAM session
          </Button>
          <Button
            fullWidth
            variant="contained"
            onClick={this.handleGetWithCustomAuth}
            sx={{ mt: 1, mb: 1 }}
          >
            GET with pool and custom authorizer
          </Button>
          <Button
            fullWidth
            variant="contained"
            onClick={this.handleUserGroupUpdate}
            sx={{ mt: 1, mb: 1 }}
          >
            Update User/Org/Group
          </Button>
          <Button
            name="logOut"
            fullWidth
            onClick={this.handleLogOut}
            variant="contained"
            sx={{ mt: 1, mb: 1 }}
          >
            Log Out
          </Button>
        </Box>
      </Box>
    )
  }
}

export default Login