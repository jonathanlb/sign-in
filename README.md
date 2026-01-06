# sign-in: Cognito authentication for WordPress

Protect WordPress content behind a shortcode tag and authenticate using AWS Cognito.
**Absolutely no warranty or guarantee is provided with this software.  Use at your own risk!**

## Installation

- Change the caching settings in your WordPress site so that *web pages* are not cached.  Assets are OK, but rendering a stale page could provide unauthorized access to a user or render an eternal login dialog.
- Download the sign-in plugin to your plugins directory, e.g. `wp-content/plugins/sign-in`
- From the `sign-in` install directory, run `composer update`

### AWS Setup
- Create a AWS user pool and client id.
```
aws cognito-idp create-user-pool --pool-name POOL_NAME \
    --username-attributes "email" \
    --query 'UserPool.Id'
aws cognito-idp create-user-pool-client --user-pool-id POOL_NAME \
    --client-name CLIENT_NAME \
    --refresh-token-validity 90 \
    --read-attributes email \
    --explicit-auth-flows ALLOW_USER_PASSWORD_AUTH ALLOW_REFRESH_TOKEN_AUTH \
    --enable-token-revocation
```
  - Enter the user pool and client ids on the Sign In Settings page.
  - If you're using the AWS web console, make sure that the client id has user-password authentication enabled.
- Create an IAM user with permission to list users. The only permission required is
```
{
	"Version": "2012-10-17",
	"Statement": [
		{
			"Effect": "Allow",
			"Action": [
				"cognito-idp:ListUsers"
			],
			"Resource": "<user-pool-arn>"
		}
	]
}
```
- Download the user's AWS access key id and secret access key and save them in `wp-content/plugins/sign-in/credentials` which will have the form
```
[your-profile-to-store-in-settings]
aws_access_key_id=AKIAXYZ890
aws_secret_access_key=asdfghjkl
```
- Make sure that the credentials file is not readable by the public, e.g. the link `https://yourhost.me/wp-content/plugins/sign-in/credentials` , is not viewable. Options to protect the files might be to move the file elsewhere on your host or add the restriction to an `.htaccess`
```
<Files "credentials">
    Order Allow,Deny
    Deny from all
</Files>
```
Failure to protect the credentials file will expose all the user information stored in Cognito to the world, but not the passwords to access your site.

### Plugin Settings
- Navigate your browser to your site's WordPress dashboard and activate the sign-in plugin.
- From the WordPress dashboard, select "Settings -> sign-in"
  - Enter the security profile name for the AWS access key and secret when you created the AWS user.
  - Fill in the client and user-pool ids from the second step.

### Plugin Use
- Create a page with content `[sign_in_require_auth]`
  - All content following the brackets will filtered out and replaced with a login dialog unless the user successfully authenticates with an email and password stored by Cognito.
- You can add a logout button with the shortcode `[sign_in_logout]` to any page containing the `[sign_in_require_auth]` shortcode.
  - Do not use the logout button on pages not requiring authentication.  The filter will not catch the shortcode and your viewers will see it.

## Maintainence

- **Linting:** `npm run lint`
- **Code sniffing:** `npm run sniff`
- **Unit testing:** 
  - For testing, we use the @wordpress/env npm package.
    - From the plugin directory, run `npm i`
    - I'm sure I've forgotten all the steps to set up [wp-env](https://www.npmjs.com/package/@wordpress/env), but make sure Docker is running...
  - `npm run wp-env-start`
  - `npm t` # ad nausea...
  - `npm run wp-env-stop`

## TODOs

- Alpha testing.
- Improve unit-test coverage.
- Normalize strings.
