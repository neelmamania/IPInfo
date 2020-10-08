
/**
 * This is an example using pure react, with no JSX
 * If you would like to use JSX, you will need to use Babel to transpile your code
 * from JSK to JS. You will also need to use a task runner/module bundler to
 * help build your app before it can be used in the browser.
 * Some task runners/module bundlers are : gulp, grunt, webpack, and Parcel
 */

import * as Setup from "./setup_page.js";

define(["react", "splunkjs/splunk"], function(react, splunk_js_sdk){
  const e = react.createElement;

  class SetupPage extends react.Component {
    constructor(props) {
      super(props);

      this.state = {
	stanza: 'ip_info_configuration',
        api_url: '',
        api_token: '',
        proxy_enable: '',
	proxy_url:'',
	proxy_port: ''
      };

      this.handleChange = this.handleChange.bind(this);
      this.handleSubmit = this.handleSubmit.bind(this);
    }

    handleChange(event) {
      this.setState({ ...this.state, [event.target.name]: event.target.value})
    }

    async handleSubmit(event) {
      event.preventDefault();

      await Setup.perform(splunk_js_sdk, this.state)
    }

    render() {
      return e("div", null, [
        e("h2", null, "IP Info Setup Page"),
        e("div", null, [
          e("form", { onSubmit: this.handleSubmit }, [
            e("label", null, [
              "API URL",
              e("input", { type: "text", name: "api_url", id:"api_url", value: this.state.api_url, onChange: this.handleChange })
            ]),
            e("label", null, [
              "API TOKEN",
              e("input", { type: "text", name: "api_token", id:"api_token", value: this.state.api_token, onChange: this.handleChange })
            ]),
            e("label", null, [
              "Proxy Enable",
              e("input", { type: "radio", name: "proxy_enable", id:"yes", value: "yes", onChange: this.handleChange }),
	      e("label", null , "Yes"),
	      e("input", { type: "radio", name: "proxy_enable", id:"no", value: "no", onChange: this.handleChange }),
	      e("label", null , "No")
            ]),
            e("label", null, [
              "Proxy URL",
              e("input", { type: "text", name: "proxy_url",id:"proxy_url" ,value: this.state.proxy_url, onChange: this.handleChange })
            ]),
	    e("label", null, [
              "Proxy Port",
              e("input", { type: "text", name: "proxy_port", id:"proxy_port", value: this.state.proxy_port, onChange: this.handleChange })
            ]),
            e("input", { type: "submit", value: "Submit" })
          ])
        ])
      ]);
    }
  }

  return e(SetupPage);
});
