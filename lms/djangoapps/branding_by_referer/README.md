
Usage example (Site configuration):

```json
{
  "THEME_OPTIONS":{
    "BRANDING_BY_REFERER":{
      "example.com":{
        "navigation":{
          "logo_src":"https://i.imgur.com/cL1326Z.jpg"
        }
      }
    }
  }
}
```

SetConfigurationByReferer middleware:

This middleware checks if the current logged-in user has a marketing site referer preference. If so, it overwrites some values of the site configuration based on the referer.
It depends on the SetBrandingByReferer middleware to apply the configuration overwrites, as that middleware sets the referer preference for the current logged-in user. Therefore this middleware must be located below the SetBrandingByReferer one in the MIDDLEWARE_CLASSES setting

Usage example of configuration by referer (Site configuration). In this case we are overwriting the setting PLATFORM_NAME when the referer preference is example.com:

```json
{
  "CONFIGURATION_BY_REFERER":{
    "example.com":{
      "PLATFORM_NAME":"Example platform"
    }
  }
}
```