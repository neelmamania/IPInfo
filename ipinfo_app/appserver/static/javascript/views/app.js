
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
        proxy_enable: 'No',
	proxy_url:'https://127.0.0.1',
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
			e("div", {class:"row"}, [
				e("link",{rel:"stylesheet",href:"https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/css/bootstrap.min.css"}),
				e("form", { autoComplete:"off", class :"",onSubmit: this.handleSubmit }, [
					e("div", {class:"form-group"}, [
						e("label", {class:"col-md-2"}, "API URL"),
						e("div", {class:"col-md-4 autocomplete"},[
							e("input", { type: "text", name: "api_url", id:"api_url", value: this.state.api_url, onChange: this.handleChange,class:"form-control" })
						])
					]),
					e("div",{class:"clearfix"}),
					e("div", {class:"form-group"}, [
						e("label", {class:"col-md-2"}, "API TOKEN"),
						e("div", {class:"col-md-4 autocomplete"},[
							e("input", { type: "text", name: "api_token", id:"api_token", value: this.state.api_token, onChange: this.handleChange,class:"form-control" })
						])
					]),
					e("div",{class:"clearfix"}),
					e("div", {class:"form-group"}, [
						e("label", {class:"col-md-2"}, "Proxy Enable"),
						e("div", {class:"col-md-4 autocomplete"},[
							e("input", { type: "radio", name: "proxy_enable", id:"proxy_yes", value: "Yes", onChange: this.handleChange}),
							e("label", {style:{width:"40px"}}, "Yes"),
							e("input", { type: "radio", name: "proxy_enable", id:"proxy_no", value: "No", onChange: this.handleChange,checked:"checked" }),
							e("label", null, "No"),
							e("br",null,null),
						])
					]),
					e("div",{class:"clearfix"}),
					e("div", {class:"form-group"}, [
						e("label", {class:"col-md-2"}, "Proxy URL"),
						e("div", {class:"col-md-4 autocomplete"},[
							e("input", { type: "text", name: "proxy_url", id:"proxy_url", onChange: this.handleChange,class:"form-control" })
						])
					]),
/*					e("div",{class:"clearfix"}),
					e("div", {class:"form-group"}, [
						e("label", {class:"col-md-2"}, "Proxy Port"),
						e("div", {class:"col-md-4 autocomplete"},[
							e("input", { type: "text", name: "proxy_port", id:"proxy_port", value: this.state.proxy_port, onChange: this.handleChange,class:"form-control" })
						])
					]),
*/					e("div",{class:"clearfix"}),
					e("div", {class:"form-group"}, [
						e("div", {class:"col-md-offset-2 col-md-10"}, [
							e("input", { type: "submit", value: "Submit" })
						])
					]),
//					e("input", { type: "submit",id:"submitbtn", value: "Submit" })
				])
			])
		]);
	}

  }

  return e(SetupPage);
});
