// Copyright 2016 The Sandpass Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

(function() {
  'use strict';

  var pwgenUrl;
  var queryEncode = function(s) {
    return encodeURIComponent(s).replace('%20', '+');
  };
  var getSelectedMode = function() {
    var btns = document.querySelectorAll('#pwgenForm [name="mode"]');
    for (var i = 0; i < btns.length; i++) {
      if (btns[i].checked) {
        return btns[i].value;
      }
    }
    return '';
  };
  var getModeArea = function(mode) {
    if (mode == '') {
      return document.getElementById('normalModeOptions');
    } else if (mode == 'phrase') {
      return document.getElementById('passphraseModeOptions');
    } else {
      return null;
    }
  };
  var inputQueryString = function(inputs) {
    var q = '';
    for (var i = 0; i < inputs.length; i++) {
      if (inputs[i].type == 'checkbox') {
        if (inputs[i].checked) {
          if (q) {
            q += '&';
          }
          q += queryEncode(inputs[i].name) + '=' + (inputs[i].value ? queryEncode(inputs[i].value) : 'on');
        }
      } else {
        if (q) {
          q += '&';
        }
        q += queryEncode(inputs[i].name) + '=' + queryEncode(inputs[i].value);
      }
    }
    return q;
  };
  var setError = function(msg) {
    var box = document.querySelector('#pwgenForm .error');
    if (msg) {
      box.hidden = false;
      box.textContent = msg;
    } else {
      box.hidden = true;
    }
  };
  var generate = function(e) {
    e.stopPropagation();
    e.preventDefault();

    var req = new XMLHttpRequest();
    var u = pwgenUrl;
    var mode = getSelectedMode();
    u += '?mode=' + queryEncode(mode);
    var q = inputQueryString(getModeArea(mode).querySelectorAll('input'));
    if (q) {
      u += '&' + q;
    }
    req.open('GET', u, true /* async */);
    req.onload = function() {
      if (this.status >= 200 && this.status < 400) {
        document.getElementById('entryPassword').value = this.response;
        setError('');
      } else {
        setError(this.response);
      }
    };
    req.onerror = function() {
      setError('Network error');
    };
    req.send();
  };
  var updateMode = function() {
    var areas = document.querySelectorAll('.pwgenOptions');
    for (var i = 0; i < areas.length; i++) {
      areas[i].hidden = true;
    }
    var mode = getSelectedMode();
    if (mode == '') {
      document.getElementById('normalModeOptions').hidden = false;
    } else if (mode == 'phrase') {
      document.getElementById('passphraseModeOptions').hidden = false;
    }
  };
  var onload = function() {
    var form = document.getElementById('pwgenForm');
    pwgenUrl = form.getAttribute('action');
    form.addEventListener('submit', generate);

    updateMode();
    var btns = document.querySelectorAll('#pwgenForm [name="mode"]');
    for (var i = 0; i < btns.length; i++) {
      btns[i].addEventListener('click', updateMode);
    }
  };
  if (document.readyState != 'loading') {
    onload();
  } else {
    document.addEventListener('DOMContentLoaded', onload);
  }
})();
