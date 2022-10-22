# Levo Burp Extension
Build OpenApi specs from Burp's traffic using Levo.ai. Also detect and classify the PII and annotate specs with
the PII details.

**How does that work?**
* Bring up Levo's Satellite service locally using Docker compose. 
  Docs: https://docs.levo.ai/api-observability/install-guide/install-satellite#install-on-linux-host-via-docker-compose
* Turn on sending traffic to Levo in Burp using config menu
* Start using Burp like you normally do. Extension sends the API traffic (only few valid content types are supported)
  to Levo's Satellite
* Levo's Satellite that's running locally will process the traffic, sends **OpenApi** specs to Levo's cloud service.
  You can view the specs in Levo's UI.
* PII detection also fully runs locally in Satellite and only the PII types are sent to Levo's cloud service.
  You can view the PII types in Levo's UI.
* **None of your API data is sent to Levo's cloud service. Only OpenApi specs are sent to Levo's cloud service.**

## Options

### Scope
By default, OpenApi specs are built for all the traffic. 
You can limit the scope to target scopes only by enabling the option in the config menu.

### Enable sending traffic to Levo
By default, the traffic isn't sent to Levo. You can enable it using the config menu.

## Possible improvements
* Supporting remote Satellite so that teams can have a central Satellite hosted in their VPC.
* Making Levo's Satellite optional. Levo can host the Satellite provided user is comfortable with that option.
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

**0.1.0**
 * Initial release of Levo's Burp extension builds OpenApi specifications for your APIs based on Burp HTTP traffic.
 * Detects and classifies PII in the traffic and annotates the OpenApi specs with the PII details.
 * In this version, you need to run Levo's Satellite service locally on your machine using docker-compose. We plan to
   make this optional in the future.

# Feedback/Q&A
Please don't hesitate to reach out to us at support@levo.ai with suggestions, feedback, or questions.
