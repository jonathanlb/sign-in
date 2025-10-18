# sign-in: Cognito authentication for WordPress

Protect WordPress content behind a shortcode tag and authenticate using AWS Cognito.

## Setup
- Create a AWS user pool and client id.
  - Make sure that the client id has user-password authentication enabled.
- Download the sign-in plugin to your plugins directory, e.g. `wp-content/plugins/sign-in`
  - From the plugin directory, run `npm i`
  - I'm sure I've forgotten all the steps to set up [wp-env](https://www.npmjs.com/package/@wordpress/env), but make sure Docker is running...
- Navigate your browser to your site's WordPress dashboard and activate the sign-in plugin.
- From the WordPress dashboard, select "Settings -> sign-in"
  - Enter the path, either relative to the `sign-in` plugin directory or absolute to your AWS credentials file.  If you don't specify a filename, sign-in will attempt to read a file called `credentials` in its plugin directory.
  - Enter the security profile name.  If none is specified, sign-in will use `default`.
  - Fill in the client and user-pool ids from the first step.
- Create a page with content `[sign_in_require_auth]`
  - All content following the brackets will filtered out and replaced with a login dialog unless the user successfully authenticates with an email and password stored by Cognito.
  - You can override the settings set in the dashboard with tags inside the shortcode:
    - `aws_credentials_path`
    - `aws_client_id`
    - `aws_profile`
    - `aws_region`
    - `aws_version`
    - `cognito_user_pool_id`

## Maintainence

- **Linting:** `npm run lint`
- **Code sniffing:** `npm run sniff`
- **Unit testing:** 
  - `npm run wp-env-start`
  - `npm t` # ad nausea...
  - `npm run wp-env-stop`

## TODOs

- Provide [reset password functionality.](https://docs.aws.amazon.com/aws-sdk-php/v3/api/api-cognito-idp-2016-04-18.html#forgotpassword)
- Provide log out button.