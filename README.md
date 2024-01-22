# Levo Burp Extension
Build OpenApi specs from Burp's traffic using Levo.ai. Also detect and classify the PII,
and annotate specs with the PII details.

## How does this work?
**In Levo's SaaS UI**
* Create a free-forever account on [Levo.ai](https://levo.ai). No credit card required.

***Drop us a mail so that we can host a satellite for you***
* Drop us a mail at support@levo.ai with the subject line - 

    `Need Hosted Satellite for Burp Suite.`
* We will bring up a hosted satellite for you in no time, so that you can utilize all of Levo's incredible services.
* Login to Levo at https://app.levo.ai and copy the org-id from the user profile in the top right.

  `User profile -> User settings -> Organizations -> Click on Copy under Organization ID`
* Enter the satellite url as - `collector.levo.ai` in the Burp config menu.
* Check out the Advanced section below for instructions to setup a satellite locally.

**In Burp**
* Turn on sending traffic to Levo in Burp using config menu
* Start using Burp like you normally do. Extension sends the API traffic (only few valid content types are supported)
  to Levo's Satellite
* Levo's Satellite processes the traffic, extracts API specs and sends them to Levo's SaaS.
  You can view the specs in Levo's UI.
* PII detection also fully runs locally in Satellite and only the PII types are sent to Levo's SaaS.
  You can view the PII types in Levo's UI.
* **None of your API data is sent to Levo's cloud service. Only API specs are sent.**

## Options

### Scope
By default, OpenApi specs are built for all the traffic. 
You can limit the scope to target scopes only by enabling the option in the config menu.

### Enable sending traffic to Levo
By default, the traffic isn't sent to Levo. You can enable it using the config menu.

## Possible improvements
* Showing the OpenApi specs and PII types in Burp UI.
* Allow triggering Levo security testing from Burp UI.

# Build the extension JAR file

Use the following command and the JAR file will be located in folder **build/lib**:

```
$ gradlew clean fatJar
```

# Nightly build
Nightly build publishes the jar as an artifact in this repo. You can download and use it directly with Burp.

# Changelog

**0.1.7**
 * Fixed bugs in setting Levo's Satellite URL correctly.
 * We also now support sending traffic to Levo's Satellite running in Levo's SaaS. Login to Levo's SaaS UI
   and get the Satellite URL from Settings -> Organization -> Satellite.

**0.1.6**
 * Allowing Levo's Satellite URL address to be configured in the config menu. Default is http://localhost:9999

**0.1.0**
 * Initial release of Levo's Burp extension builds OpenApi specifications for your APIs based on Burp HTTP traffic.
 * Detects and classifies PII in the traffic and annotates the OpenApi specs with the PII details.
 * In this version, you need to run Levo's Satellite service locally on your machine using docker-compose. We plan to
   make this optional in the future.

## Advanced

***Running Levo's Satellite locally so that you don't send API traffic to Levo's cloud***
* Login to Levo at https://app.levo.ai and copy Levo's auth key from the user profile in the top right.

  `User profile -> User settings -> Keys -> Get Satellite Authorization Key`

* Bring up Levo's Satellite service locally using this docker run command.

  `docker run -p 9999:9999 -e LEVOAI_AUTH_KEY=<auth key from Levo.ai> levoai/satellite-single-node`

# Feedback/Q&A
Please don't hesitate to reach out to us at support@levo.ai with suggestions, feedback, or questions.
