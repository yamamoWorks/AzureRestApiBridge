var https = require("https");
var url = require('url');
var crypto = require("crypto");

module.exports = function (context, fncReq) {
    var urlInfo = url.parse(fncReq.endpoint, true);
    var sasToken = generateSasToken(urlInfo.host + urlInfo.path, fncReq.sharedAccessKey, fncReq.policyName, 5);
    var data = JSON.stringify(fncReq.data);

    var options = {
        host: urlInfo.host,
        method: "POST",
        path: urlInfo.path,
        headers: {
            "Content-Type": "application/json",
            "Authorization": sasToken,
            "Content-Length": Buffer.byteLength(data)
        }
    };

    var hubReq = https.request(options, hubRes => {
        var body = "";
        hubRes.setEncoding("utf-8");
        hubRes.on("data", chunk => body = body + chunk);
        hubRes.on("end", () => {
            context.res = {
                status: hubRes.statusCode,
                body: body
            };
            context.done();
        })
    });

    hubReq.on("error", e => {
        context.res = {
            status: 500,
            body: e.message
        };
        context.done();
    });

    hubReq.write(data);
    hubReq.end();
};

// https://docs.microsoft.com/ja-jp/azure/iot-hub/iot-hub-devguide-security#security-tokens
var generateSasToken = function(resourceUri, signingKey, policyName, expiresInMins) {
    resourceUri = encodeURIComponent(resourceUri);

    // Set expiration in seconds
    var expires = (Date.now() / 1000) + expiresInMins * 60;
    expires = Math.ceil(expires);
    var toSign = resourceUri + '\n' + expires;

    // Use crypto
    var hmac = crypto.createHmac('sha256', new Buffer(signingKey, 'base64'));
    hmac.update(toSign);
    var base64UriEncoded = encodeURIComponent(hmac.digest('base64'));

    // Construct autorization string
    var token = "SharedAccessSignature sr=" + resourceUri + "&sig="
    + base64UriEncoded + "&se=" + expires;
    if (policyName) token += "&skn="+policyName;
    return token;
};
