<html>
<head>
    <title>Please Log In</title>
</head>
<body>
<h1>Please Log In</h1>

<a href="${server_uri}/oauth2/authorize?response_type=code&client_id=${client_id}&scope=openid&redirect_uri=http://127.0.0.1:8090/${handler_uri}">
    Login
</a>
</body>
</html>