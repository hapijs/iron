# Add Expiration
* Author: Myungcheol Doo <myungcheol@gmail.com>

This document explains a proposal for supporting to include an optional expiration time somewhere in the iron sealed object and validate it when unsealing.

## Proposed Solution 1
A very simple solution to this problem is to add **timestamp** of expiration time at the end of **sealed** variable. The decision of optional expiration time is determined by **options**. 

````
exports.defaults = {
  ....
  , expiration : {
    used : false,     // expiration is optional otherwise set true
    timeUnit: null,   
    timeDiff: null, // new expiration time = currentTime + (timeDiff * timeUnit)
  }
};

// time units in milliseconds
exports.timeUnits = {
  second: 1000,
  minute: 60000,
  hour: 3600000,
  day: 86400000
};

exports.seal = function(object, password, options, callback) {
  ....
  
  var sealed = macBaseString + '*' + mac.salt + '*' + mac.digest;
  if (options.expiration.used === true && options.expiration.timeUnit && timeUnits[options.expiration.timeUnit] && options.expirataion.timeDiff) {
    var curTime = new Date().valueOf();
    sealed = sealed + '*' + new Date(curTime + (options.expiration.timeUnit * options.expiration.timeDiff)).valueOf();
  }
  return callback(null, sealed);
};
````

### Pros
Only a few lines of code are added to support expiration. The expiration time could be checked at the start of **unseal** function as a 8th parts, **parts[7]**.

### Cons
It is a plain text so that any client can replace it with a new expiration time or remove it as if there is no expiration time. 

## Proposed Solution 2
Like the above solution, we can set expiration options in the **options** variable. In this solution, we create a new object with the passed original object and the computed expiration time. Then we encrypt the newly created object. In unsealing part, the expiration time from the decrypted object is used to determine if the encryption has expired or not.

````
exports.seal = function (object, password, options, callback) {
  if (options.expiration.used === true && options.expiration.timeUnit && timeUnits[options.expiration.timeUnit] && options.expirataion.timeDiff) {
    var curTime = new Date().valueOf();
    // create a new object by attaching the expiration time
    object = {
      obj: object,
      expirationTime: new Date(curTime + (options.expiration.timeUnit * options.expiration.timeDiff)).valueOf()
    };
  }  

  var objectString = JSON.stringify(object);
  
  ...
});

exports.unseal = function (sealed, password, options, callback) {
  ...
  export.decrypt(password, decryptOptions, encrypted, function (err, decrypted) {
    var object = null;
    try {
      object = JSON.parse(decrypted);
      
      // optional expiration time has been set?
      if (object.expirationTime) {
        var curTime = new Date().valueOf();
        var expTime = new Date(object.expirationTime).valueOf();

        if (curTime <= expTime) {
          // detach expiration time
          object = object.obj;
        } else {
          return callback(Boom.internal('This encryption has expired'));
        }
    }
    catch (err) {
      return callback(Boom.internal('Failed parsing sealed object JSON: ' + err.message));
    }

    return callback(null, object);
  });
});
````

### Pros
The expiration time is also encrypted as a part of original object. Therefore, the expiration time cannot be modified from the client side.

### Cons
We cannot determine if the encryption has expired until we finally decrypt the string. 
