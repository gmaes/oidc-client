const contextParse = function (json) {
  var context = {};
  if (json.auth_time) {
    // @ts-ignore
    context.timestamp = new Date(json.auth_time * 1000);
  }
  if (json.acr) {
    // @ts-ignore
    context.class = json.acr;
  }
  if (json.amr) {
    // @ts-ignore
    context.methods = json.amr;
  }

  return context;
};

export default contextParse;
