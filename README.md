# Levo Burp Extension
Build OpenApi specs from Burp's traffic using Levo.ai. Also detect and classify the PII, and annotate specs with the PII details.

## How does this work?

***[Book a Demo](https://www.levo.ai/book-demo) to learn about the Levo.ai***

**Pre-requisites**
* **Account:** Create an account on the [Levo.ai](https://app.levo.ai) SaaS platform.
* **Levo Satellite:** Follow the instructions for [Satellite Installation](https://docs.levo.ai/install-satellite).
  - Alternatively, email our [Support](mailto:support@levo.ai) with the subject line:

    `Need Hosted Satellite for Burp Suite.`

    We will quickly set up a hosted satellite for you, so you can take full advantage of Levo's services.
* **Organization ID:** Refer to these [instructions](https://docs.levo.ai/integrations/common-tasks#accessing-organization-ids) to obtain your organization ID from Levo's SaaS.
* **Satellite URL:** Enter the satellite URL:
  - `http://localhost:9999` for a local satellite (default) or a satellite installed via local Docker.
  - `collector.levo.ai` for the Levo-hosted satellite in the Burp config menu.
* See the Advanced section below for instructions on setting up a satellite locally.

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

**0.2.1**
 * Fixed Host header to omit default port numbers (80 for HTTP, 443 for HTTPS) per RFC 7230 standard.

**0.2.0**
 * Allow setting the environment to which the traffic is to be sent on the Levo Dashboard.

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
