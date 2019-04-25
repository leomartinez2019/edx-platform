
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