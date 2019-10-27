"use strict";

import axios from "axios";
import createHmac from "create-hmac";
import OAuth from "oauth-1.0a";
import Url from "url-parse";
import CryptoJs from "crypto-js";

/**
 * SmartStore REST API wrapper
 *
 * @param {Object} opt
 */
export default class SmartStoreRestApi {
  /**
   * Class constructor.
   *
   * @param {Object} opt
   */
  constructor(opt) {
    if (!(this instanceof SmartStoreRestApi)) {
      return new SmartStoreRestApi(opt);
    }

    opt = opt || {};

    if (!opt.url) {
      throw new OptionsException("url is required");
    }

    if (!opt.consumerKey) {
      throw new OptionsException("consumerKey is required");
    }

    if (!opt.consumerSecret) {
      throw new OptionsException("consumerSecret is required");
    }

    this.classVersion = "1.0.1";
    this._setDefaultsOptions(opt);
  }

  /**
   * Set default options
   *
   * @param {Object} opt
   */
  _setDefaultsOptions(opt) {
    this.url = opt.url;
    this.wpAPIPrefix = opt.wpAPIPrefix || "wp-json";
    this.version = opt.version || "wc/v3";
    this.isHttps = /^https/i.test(this.url);
    this.consumerKey = opt.consumerKey;
    this.consumerSecret = opt.consumerSecret;
    this.encoding = opt.encoding || "utf8";
    this.queryStringAuth = opt.queryStringAuth || false;
    this.port = opt.port || "";
    this.timeout = opt.timeout;
    this.axiosConfig = opt.axiosConfig || {};
    /*
     * Crypto MD5 & Hash 256
     */
    this.url1 = opt.url;
    this.wpAPIPrefix1 = opt.wpAPIPrefix || "wp-json";
    this.version1 = opt.version || "wc/v3";
    this.consumerKey1 = opt.consumerKey;
    this.consumerSecret1 = opt.consumerSecret;
    this.encoding1 = opt.encoding || "utf8";
    this.port1 = opt.port || "";
    this.timeout1 = opt.timeout;
    this.axiosConfig1 = opt.axiosConfig || {};
  }

  /**
   * Parse params object.
   *
   * @param {Object} params
   * @param {Object} query
   */
  _parseParamsObject(params, query) {
    for (const key in params) {
      const value = params[key];

      if (typeof value === "object") {
        for (const prop in value) {
          const itemKey = key.toString() + "[" + prop.toString() + "]";
          query[itemKey] = value[prop];
        }
      } else {
        query[key] = value;
      }
    }

    return query;
  }

  /**
   * Normalize query string for oAuth
   *
   * @param  {String} url
   * @param  {Object} params
   *
   * @return {String}
   */
  _normalizeQueryString(url, params) {
    // Exit if don't find query string.
    if (url.indexOf("?") === -1 && Object.keys(params).length === 0) {
      return url;
    }

    const query = new Url(url, null, true).query;
    const values = [];

    let queryString = "";

    // Include params object into URL.searchParams.
    this._parseParamsObject(params, query);

    for (const key in query) {
      values.push(key);
    }
    values.sort();

    for (const i in values) {
      if (queryString.length) {
        queryString += "&";
      }

      queryString += encodeURIComponent(values[i])
        .replace(/%5B/g, "[")
        .replace(/%5D/g, "]");
      queryString += "=";
      queryString += encodeURIComponent(query[values[i]]);
    }

    return url.split("?")[0] + "?" + queryString;
  }

  /**
   * Get URL
   *
   * @param  {String} endpoint
   * @param  {Object} params
   *
   * @return {String}
   */
  _getUrl(endpoint, params) {
    const api = this.wpAPIPrefix + "/";

    let url = this.url.slice(-1) === "/" ? this.url : this.url + "/";

    url = url + api + this.version + "/" + endpoint;

    // Include port.
    if (this.port !== "") {
      const hostname = new Url(url).hostname;

      url = url.replace(hostname, hostname + ":" + this.port);
    }

    if (!this.isHttps) {
      return this._normalizeQueryString(url, params);
    }

    return url;
  }


  /**
   * Get URL
   *
   * @param  {String} endpoint
   * @param  {Object} params
   *
   * @return {String}
   */
  _getUrl1(endpoint, params) {
    const api = this.wpAPIPrefix + "/";

    let url = this.url.slice(-1) === "/" ? this.url : this.url + "/";

    url = url + api + this.version + "/" + endpoint;

    // Include port.
    if (this.port !== "") {
      const hostname = new Url(url).hostname;

      url = url.replace(hostname, hostname + ":" + this.port);
    }

    return url;
  }

  /**
   * Get OAuth
   *
   * @return {Object}
   */
  _getOAuth() {
    const data = {
      consumer: {
        key: this.consumerKey,
        secret: this.consumerSecret
      },
      signature_method: "HMAC-SHA256",
      hash_function: (base, key) => {
        return createHmac("sha256", key)
          .update(base)
          .digest("base64");
      }
    };

    return new OAuth(data);
  }

  /**
   * Do requests
   *
   * @param  {String} method
   * @param  {String} endpoint
   * @param  {Object} data
   * @param  {Object} params
   *
   * @return {Object}
   */
  _request(method, endpoint, data, params = {}) {
    const url = this._getUrl(endpoint, params);
    var now = new Date(),
      timestamp = now.toISOString(),
      contentMd5Hash = null;

    let options = {
      url: url,
      method: method,       //type: options.method || 'GET',      
      responseEncoding: this.encoding,
      timeout: this.timeout,
      responseType: "json", //dataType: 'json',
      headers: {
        "User-Agent": "SmartStore REST API - JS Client/" + this.classVersion,
        Accept: "application/json, text/javascript, */*",
        "SmartStore-Net-Api-PublicKey": this.consumerKey1,
        "SmartStore-Net-Api-Date": timestamp,
      }
    };
    
    if (data) {
      options.headers["Content-Type"] = "application/json;charset=utf-8"; //contentType: 'application/json; charset=utf-8',
      // options.responseType: "json", //dataType: 'json',
      options.data = JSON.stringify(data);
    }

    // Allow set and override Axios options.
    options = { ...options, ...this.axiosConfig };

    return axios(options);
  }

  _createContentMd5Hash(content) {
    if (content && content.length > 0) {
      var hash = CryptoJs.MD5(content);

      return CryptoJs.enc.Base64.stringify(hash);
    }
    return '';
  };


  _createMessageRepresentation(contentMd5Hash, timestamp, options) {
    var result = [
      options.method.toLowerCase(),
      contentMd5Hash || '',
      "application/json, text/javascript, */*",
      options.url.toLowerCase(),
      timestamp,
      this.consumerKey1.toLowerCase()
    ].join('\n');

    return result;
  };


  _createSignature(messageRepresentation) {
    var hash = CryptoJs.HmacSHA256(messageRepresentation, this.consumerSecret1),
      signature = CryptoJs.enc.Base64.stringify(hash);

    return signature;
  };


  _createAuthorizationHeader = function (signature) {
    if (!signature || signature.length <= 0)
      return '';

    return 'SmNetHmac1 ' + signature;
  };


  /**
   * Do requests
   *
   * @param  {String} method
   * @param  {String} endpoint
   * @param  {Object} data
   * @param  {Object} params
   *
   * @return {Object}
   */
  _request1(method, endpoint, data, params = {}) {
    const url = this._getUrl(endpoint, params);
    var now = new Date(),
      timestamp = now.toISOString(),
      contentMd5Hash = null;

    let options = {
      url: url,
      method: method,       //type: options.method || 'GET',      
      responseEncoding: this.encoding,
      timeout: this.timeout,
      responseType: "json", //dataType: 'json',
      headers: {
        "User-Agent": "SmartStore REST API - JS Client/" + this.classVersion,
        Accept: "application/json, text/javascript, */*",
        "SmartStore-Net-Api-PublicKey": this.consumerKey1,
        "SmartStore-Net-Api-Date": timestamp,
      }
    };
    
    if (data) {
      if (typeof (data) === 'object')
        data = JSON.stringify(data);

      contentMd5Hash = this._createContentMd5Hash(data);

      options.headers["Content-Type"] = "application/json;charset=utf-8"; //contentType: 'application/json; charset=utf-8',
      // options.responseType: "json", //dataType: 'json',
      options.data = data;

      options.headers["Content-MD5"] = contentMd5Hash;
    }

    var messageRepresentation = this._createMessageRepresentation(contentMd5Hash, timestamp, options);
    var signature = this._createSignature(messageRepresentation);

    options.headers["Authorization"] = this._createAuthorizationHeader(signature);

    // Allow set and override Axios options.
    options = { ...options, ...this.axiosConfig };

    return axios(options);
  }


  /**
   * GET requests
   *
   * @param  {String} endpoint
   * @param  {Object} params
   *
   * @return {Object}
   */
  get(endpoint, params = {}) {
    return this._request("get", endpoint, null, params);
  }



  get1(endpoint, params = {}) {
    return this._request("get", endpoint, null, params);
  }
  /**
   * POST requests
   *
   * @param  {String} endpoint
   * @param  {Object} data
   * @param  {Object} params
   *
   * @return {Object}
   */
  post(endpoint, data, params = {}) {
    return this._request("post", endpoint, data, params);
  }


  post1(endpoint, data, params = {}) {
    return this._request("post", endpoint, data, params);
  }

  /**
   * PUT requests
   *
   * @param  {String} endpoint
   * @param  {Object} data
   * @param  {Object} params
   *
   * @return {Object}
   */
  put(endpoint, data, params = {}) {
    return this._request("put", endpoint, data, params);
  }



  put1(endpoint, data, params = {}) {
    return this._request("put", endpoint, data, params);
  }
  /**
   * DELETE requests
   *
   * @param  {String} endpoint
   * @param  {Object} params
   * @param  {Object} params
   *
   * @return {Object}
   */
  delete(endpoint, params = {}) {
    return this._request("delete", endpoint, null, params);
  }



  delete1(endpoint, params = {}) {
    return this._request("delete", endpoint, null, params);
  }
  /**
   * OPTIONS requests
   *
   * @param  {String} endpoint
   * @param  {Object} params
   *
   * @return {Object}
   */
  options(endpoint, params = {}) {
    return this._request("options", endpoint, null, params);
  }


  options1(endpoint, params = {}) {
    return this._request("options", endpoint, null, params);
  }
}

/**
 * Options Exception.
 */
export class OptionsException {
  /**
   * Constructor.
   *
   * @param {String} message
   */
  constructor(message) {
    this.name = "Options Error";
    this.message = message;
  }
}
