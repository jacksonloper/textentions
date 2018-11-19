var USEPKCE=false;
AWS.config.region="us-east-1";

////////////////////////////////
// generate the info we need to send
// to the authorize endpoint
// including a pkce challenge
function genPKCEInfo(usepkce){
	// generate random bytes
	var secretArray = new Uint8Array(32);
	window.crypto.getRandomValues(secretArray);

	// get b64 encoding of those bytes
	var secret = window.btoa(secretArray);

	// get sha of those bytes
	return crypto.subtle.digest("SHA-256",secretArray).then((secretArraySHA) => {
		var secretSHA = window.btoa(secretArraySHA);

		return {
			secret:secret,
			secretSHA:secretSHA,
			randomState: 'textentions'+Math.random(),
			usedPKCE:usepkce
		}
	});
}

//////////////////////
// update our AWS credentials
// using a jwt token 
// and use them to get
// authenticated via CognitoIdentity
function updateAWSCreds(userPoolIdToken) {
	AWS.config.credentials = new AWS.CognitoIdentityCredentials({
		IdentityPoolId: 'us-east-1:72a9b234-a9aa-465a-8034-c522d545c5dc',
		Logins: {
			'cognito-idp.us-east-1.amazonaws.com/us-east-1_84ik986WN': userPoolIdToken
		},
		region: 'us-east-1'
	});

	return new Promise((resolve,reject) => {
        AWS.config.credentials.refresh((error) => {
            if (error) {
                reject({msg:"awsInitFromSession: failed to refresh",err:error})
            } else {
                resolve({msg:"success"})
            }
        })
    })
}

///////////////////////
// try to use a code from the 
// querystring to get a user pool token
// from the userpool token endpoint
function exchangeAuthcodeForNewTokens() {
	var urlParams = new URLSearchParams(window.location.search);
	if(!urlParams.has('code')) {
		return Promise.reject({msg:"no authcode presented"})
	}
	var authcode=urlParams.get('code')
	var randomState=urlParams.get('state')
	var pkceinfo;
	try {
		pkceinfo = JSON.parse(localStorage.getItem("pkce"))
	} catch(err) {
		return Promise.reject({msg:"failed to parse pkce",err:err});
	}

	if(!pkceinfo){
		return Promise.reject({msg:"no pkceinfo!"})
	}

	if(randomState!=pkceinfo.randomState) {
		return Promise.reject({
			msg:"pkce state is incorrect; ignoring code",
			url:randomState,
			localstorage:pkceinfo.randomState
		})
	}

	// we're good to go.  let's send out a request for
	// tokens
	var formData = new FormData();
	formData.append('grant_type', 'authorization_code');
	formData.append('client_id', '2amps2ugh49mhsuk1dk67u47qf');
	formData.append('redirect_uri','https://textentions.s3.amazonaws.com/index.html');
	if(pkceinfo.usedpkce) {
		formData.append('code_verifier',pkceinfo.secret);
	}

	return fetch("https://textentions.auth.us-east-1.amazoncognito.com/oauth2/token",
	{
		method:"POST",
		headers:{
			'Content-Type': 'application/x-www-form-urlencoded'
		}
	})
}

//////////////////////
// try to use stored tokens
// to update our AWS credentials
function authenticateViaStoredToken() {
	// first check to see if we have valid userpool tokens
	var upts = localStorage.getItem("userPoolTokens");

	// hopefully there is something there 
	if(!upts) {
		return Promise.reject({msg:"No user pool tokens found"})
	}

	// try to parse it 
	var expiration;
	try {
		upts = JSON.parse(upts);
		expiration=JSON.parse(atob(upts.id_token.split('.')[1])).exp;
	} catch(err) {
		return Promise.reject({msg:"failed to parse user pool tokens",err:err})
	}

	var expiresIn=(expiration - (new Date()).getTime()/1000.0)/60.0;

	if(expiresIn<0) {
		return Promise.reject({
			msg:"user pool identity token is expired",
			expiresIn:expiresIn
		});
	}
	
	// looks good.  we have non-expired tokens.  Let's
	// try to use them
	return updateAWSCreds(upts.id_token);
}

////////////////////////////////////
/*
 _             _               _     _            _   
| | ___   __ _(_)_ ____      _(_) __| | __ _  ___| |_ 
| |/ _ \ / _` | | '_ \ \ /\ / / |/ _` |/ _` |/ _ \ __|
| | (_) | (_| | | | | \ V  V /| | (_| | (_| |  __/ |_ 
|_|\___/ \__, |_|_| |_|\_/\_/ |_|\__,_|\__, |\___|\__|
         |___/                         |___/          

*/

// widget to help with login management
var LoginWidget = function() {
	this.maindiv = document.createElement('div');

	this.status=document.createElement('div')
	this.maindiv.appendChild(this.status)

	this.choices=document.createElement('div')
	this.maindiv.appendChild(this.choices);

	this.subdiv=document.createElement('div')
	this.maindiv.appendChild(this.subdiv);

	this.setStatus("Not logged in.")

	//////////////////////////////////
	// things you might want to do:

	// try to get a new authcode from the userpool
	this.getNewAuthcodeButton = document.createElement('button');
	this.getNewAuthcodeButton.innerHTML="Get new auth code"
	this.getNewAuthcodeButton.onclick=this.getNewAuthcode.bind(this)
	this.choices.appendChild(this.getNewAuthcodeButton)

	// test dynamo
	this.testDynamoButton = document.createElement('button');
	this.testDynamoButton.innerHTML="Test dynamo"
	this.testDynamoButton.onclick=this.testDynamo.bind(this)
	this.choices.appendChild(this.testDynamoButton)


	///////////////////////////
	// let's try to get good tokens
	this.authenticate()
}

LoginWidget.prototype.testDynamo = function()
{
	var dynamo = new AWS.DynamoDB.DocumentClient();
	var params = {
      ExpressionAttributeValues: {
        ':e': 0,
        ':m': 'message',
       },
     Limit: 1,
     ScanIndexForward: false,
     KeyConditionExpression: 'messageid > :e AND partitionkey = :m',
     TableName: 'trolldb'
    };
    dynamo.query(params).promise().then((suc) => {
    	this.appendStatus("Dynamo working ok")
    },(err) => {
    	this.setStatus("Dynamo broken!" + err)
    });
}

LoginWidget.prototype.setStatus = function(stat) {
	this.status.innerHTML=stat;
}

LoginWidget.prototype.appendStatus = function(stat) {
	this.status.innerHTML=this.status.innerHTML+"<br/>" + stat;
}

LoginWidget.prototype.authenticate = function() {
	// first try to authenticate via stored token

	return authenticateViaStoredToken().catch((err) => {
		// if that fails, try to refresh
		this.setStatus("Stored tokens failed; seeking to use refresh token")
		console.error(err)
		return Promise.reject("Refresh tokens NYI")
	}).catch((err) => {
		// if that fails, try ot use an auth code in the querystring 
		console.error(err)
		return exchangeAuthcodeForNewTokens().then(authenticateViaStoredToken);
	}).then((suc) => {
		// if that succeeds, we did it!
		this.setStatus("Valid userpool tokens found")
	},(err) => {
		// if that fails, then I'm out of ideas
		this.setStatus("No valid auth code found.  You'd best try to log in again.")
		console.error(err);
		return Promise.reject(err);
	})
}

LoginWidget.prototype.clearsubdiv = function(){
	while (this.subdiv.hasChildNodes()) {
	  this.subdiv.removeChild(this.subdiv.lastChild);
	}
}

LoginWidget.prototype.getNewAuthcode = function(){
	this.clearsubdiv()

	// make a new pkce challenge
	genPKCEInfo(USEPKCE).then((pkceinfo) => {
		localStorage.setItem('pkce',JSON.stringify(pkceinfo))

		var mylink=document.createElement('a');
		if(pkceinfo.usedpkce){
			mylink.href="https://textentions.auth.us-east-1.amazoncognito.com/oauth2/authorize?response_type=code&client_id=2amps2ugh49mhsuk1dk67u47qf&redirect_uri=https://textentions.s3.amazonaws.com/index.html&code_challenge_method=S256&code_challenge="+pkceinfo.secretSHA+"&scope=email+openid&state="+pkceinfo.randomState;
		} else {
			mylink.href="https://textentions.auth.us-east-1.amazoncognito.com/oauth2/authorize?response_type=code&client_id=2amps2ugh49mhsuk1dk67u47qf&redirect_uri=https://textentions.s3.amazonaws.com/index.html&scope=email+openid&state="+pkceinfo.randomState;
		}

		mylink.innerHTML="Authenticate"
		this.subdiv.appendChild(mylink);

		var div=document.createElement('div')
		div.innerHTML=mylink.href
		this.subdiv.appendChild(div)
	})
}