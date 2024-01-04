resource "azurerm_application_gateway" "application_gateway" {
    for_each = local.application_gateway
    name = each.value.name
    resource_group_name = var.resource_group_output[each.value.resource_group_name].name
    location = each.value.location
    tags = each.value.tags

    sku {
        name = each.value.sku.name
        tier = each.value.sku.tier
        capacity = each.value.sku.capacity
    }

    enable_http2 = each.value.enable_http2
    zones = each.value.zones

    gateway_ip_configuration {
      name = each.value.gateway_ip_configuration.name
      subnet_id = var.subnet_output[each.value.gateway_ip_configuration.subnet_name].id
    }

    dynamic "frontend_port" {
      for_each = {for frontend_port in each.value.http_listener : frontend_port.name => frontend_port}
      content {
        name = format("frontend_port-%s" , frontend_port.value.name)
        port = frontend_port.value.port
      }  
    }

    dynamic "frontend_ip_configuration" {
      for_each = each.value.frontend_ip_configuration
      content {
      name = frontend_ip_configuration.value.name
      subnet_id = frontend_ip_configuration.value.subnet_name == null ? null : var.subnet_output[frontend_ip_configuration.value.subnet_name].id
      private_ip_address = frontend_ip_configuration.value.private_ip_address == null || frontend_ip_configuration.value.private_ip_address_allocation == null ? null : frontend_ip_configuration.value.private_ip_address
      public_ip_address_id = frontend_ip_configuration.value.public_ip_name == null ? null : var.public_ip_output[frontend_ip_configuration.value.public_ip_name].id
      private_ip_address_allocation = frontend_ip_configuration.value.private_ip_address_allocation == null ? null : frontend_ip_configuration.value.private_ip_address_allocation
      private_link_configuration_name = frontend_ip_configuration.value.private_link_configuration_name
    }
    }

    dynamic"backend_address_pool" {
      for_each = each.value.backend_address_pool
      content {
        name = backend_address_pool.value.name
        fqdns = backend_address_pool.value.fqdns == null ? null : backend_address_pool.value.fqdns
        ip_addresses = backend_address_pool.value.ip_addresses == null ? null : backend_address_pool.value.ip_addresses
      }
    }

    dynamic "backend_http_settings" {
      for_each = each.value.backend_http_settings
      content {
      name = backend_http_settings.value.name
      cookie_based_affinity = backend_http_settings.value.cookie_based_affinity
      affinity_cookie_name = backend_http_settings.value.affinity_cookie_name
      path = backend_http_settings.value.path
      port = backend_http_settings.value.port
      probe_name = backend_http_settings.value.probe_name
      protocol = backend_http_settings.value.protocol
      request_timeout = backend_http_settings.value.request_timeout
      host_name = backend_http_settings.value.pick_host_name_from_backend_address != true ? backend_http_settings.value.host_name : null
      pick_host_name_from_backend_address = backend_http_settings.value.pick_host_name_from_backend_address == null ? false : backend_http_settings.value.pick_host_name_from_backend_address
      trusted_root_certificate_names = backend_http_settings.value.trusted_root_certificate_names
      connection_draining {
        enabled = backend_http_settings.value.connection_draining.enabled
        drain_timeout_sec = backend_http_settings.value.connection_draining.drain_timeout_sec
      }
      }
      
    }

     dynamic "http_listener" {
      for_each = each.value.http_listener
      content {
        name    = format("listener-%s", http_listener.value.name)
        frontend_ip_configuration_name = http_listener.value.frontend_ip_configuration_name
        frontend_port_name  = format("frontend_port-%s" , http_listener.value.name)
        host_name   = lower(http_listener.value.listener_type) == "basic" || lower(http_listener.value.listener_type) == "multisite/multiple" ?  null : http_listener.value.host_name
        host_names  = lower(http_listener.value.listener_type) == "basic" || lower(http_listener.value.listener_type) == "multisite/single" ?  null : http_listener.value.host_names
        protocol = http_listener.value.protocol
        ssl_certificate_name  = http_listener.value.ssl_certificate_name
        firewall_policy_id  = length(regexall("^waf", lower(each.value.sku.tier))) > 0  && http_listener.value.web_application_firewall_name != null ? var.web_application_firewall_output[http_listener.value.web_application_firewall_name].id: null
        dynamic "custom_error_configuration" {
          for_each = http_listener.value.custom_error_configuration
          content {
           status_code = custom_error_configuration.value.status_code
           custom_error_page_url  = custom_error_configuration.value.custom_error_page_url 
          }  
        }
      }
        
    }

    dynamic "identity" {
      for_each = length([for identity_key in each.value.identity : keys(identity_key)]) > 0 ? each.value.identity : []    #length(keys(each.value.identity))
      content {
      type = identity.value.type
      identity_ids = identity.value.identity_ids
      }
       
    }
    
    dynamic"private_link_configuration" {
      for_each = length([for private_link_key in each.value.private_link_configuration : keys(private_link_key) ])  > 0 ? each.value.private_link_configuration : []          #length(keys(each.value.private_link_configuration))
      content {
        name = private_link_configuration.value.name
        dynamic "ip_configuration" {
          for_each = private_link_configuration.value.ip_configuration
          content{
            name = ip_configuration.value.name
            subnet_id = var.subnet_output[ip_configuration.value.subnet_name].id
            private_ip_address_allocation = ip_configuration.value.private_ip_address != null ? "Static" : ip_configuration.value.private_ip_address_allocation
            primary = ip_configuration.value.primary
            private_ip_address = ip_configuration.value.private_ip_address
          }   
      }
      }
      
    }

    dynamic "probe" {
      for_each = each.value.probe
      content {
        name = probe.value.name
        host = probe.value.pick_host_name_from_backend_http_settings != true ? probe.value.host : null
        pick_host_name_from_backend_http_settings = probe.value.pick_host_name_from_backend_http_settings == null || false ? false : probe.value.pick_host_name_from_backend_http_settings
        interval = probe.value.interval
        protocol = probe.value.protocol
        path = probe.value.path
        timeout = probe.value.timeout
        unhealthy_threshold = probe.value.unhealthy_threshold
        port = probe.value.port
        match {
          body = probe.value.match.body
          status_code = probe.value.match.status_code
        }
      }
      
    }

    dynamic "request_routing_rule" {
      for_each = each.value.request_routing_rule
      content {
      name = request_routing_rule.value.name
      rule_type = request_routing_rule.value.rule_type
      http_listener_name = format("listener-%s", request_routing_rule.value.http_listener_name)
      backend_address_pool_name = request_routing_rule.value.backend_address_pool_name
      backend_http_settings_name = request_routing_rule.value.backend_http_settings_name
      redirect_configuration_name = request_routing_rule.value.redirect_configuration_name
      rewrite_rule_set_name = request_routing_rule.value.rewrite_rule_set_name
      url_path_map_name = request_routing_rule.value.url_path_map_name
      priority = request_routing_rule.value.priority
      }
    }
  
    global {
      request_buffering_enabled = each.value.global.request_buffering_enabled 
      response_buffering_enabled = each.value.global.response_buffering_enabled
    }
    
    dynamic "ssl_certificate" {
      for_each = each.value.ssl_certificate
      content {
        name = ssl_certificate.value.name
        key_vault_secret_id = format("https://%s.vault.azure.net/secrets/%s",ssl_certificate.value.Key_vault_name,ssl_certificate.value.secret_name)
      }
    }

    dynamic "url_path_map" {
      for_each = each.value.url_path_map
      content {
      name = url_path_map.value.name
      default_backend_address_pool_name = url_path_map.value.default_redirect_configuration_name == null ? url_path_map.value.default_backend_address_pool_name : null
      default_backend_http_settings_name = url_path_map.value.default_redirect_configuration_name == null ? url_path_map.value.default_backend_http_settings_name : null
      default_redirect_configuration_name = url_path_map.value.default_backend_address_pool_name == null && url_path_map.value.default_backend_http_settings_name == null ? url_path_map.value.default_redirect_configuration_name : null
      default_rewrite_rule_set_name = url_path_map.value.default_rewrite_rule_set_name
      dynamic "path_rule" {
        for_each = url_path_map.value.path_rule
        content {
        name = path_rule.value.name
        paths = path_rule.value.paths
        backend_address_pool_name = path_rule.value.redirect_configuration_name == null ? path_rule.value.backend_address_pool_name : null
        backend_http_settings_name = path_rule.value.redirect_configuration_name == null ? path_rule.value.backend_http_settings_name : null
        redirect_configuration_name = path_rule.value.backend_address_pool_name == null && path_rule.value.backend_http_settings_name == null ? path_rule.value.redirect_configuration_name :null
        rewrite_rule_set_name = path_rule.value.rewrite_rule_set_name
        firewall_policy_id = length(regexall("^waf", lower(each.value.sku.tier))) > 0 && path_rule.value.web_application_firewall_name != null ? var.web_application_firewall_output[path_rule.value.web_application_firewall_name].id: null          
        }
      }        
      }
  
    }

   dynamic "trusted_root_certificate" {
    for_each  = each.value.trusted_root_certificate
    content {
      name  = trusted_root_certificate.value.name
      key_vault_secret_id = format("https://%s.vault.azure.net/secrets/%s",trusted_root_certificate.value.Key_vault_name,trusted_root_certificate.value.secret_name)
    }
   }

    
    #  firewall_policy_id = length(regexall("^waf", lower(each.value.sku.tier))) > 0 && each.value.waf_configuration != null ? var.web_application_firewall_output[each.value.web_application_firewall_name].id: null 
    #  force_firewall_policy_association = length(regexall("^waf", lower(each.value.sku.tier))) > 0 && each.value.waf_configuration != null ? true : false

    dynamic "waf_configuration" {
      for_each = length(regexall("^waf", lower(each.value.sku.tier))) > 0 ? each.value.waf_configuration : []
      content {
      enabled = waf_configuration.value.enabled
      firewall_mode = waf_configuration.value.firewall_mode
      rule_set_type = waf_configuration.value.rule_set_type
      rule_set_version = waf_configuration.value.rule_set_version
      
      dynamic "disabled_rule_group" {
        for_each = waf_configuration.value.disabled_rule_group
        content {
          rule_group_name = disabled_rule_group.value.rule_group_name
          rules = disabled_rule_group.value.rules
        }

      }

      file_upload_limit_mb = waf_configuration.value.file_upload_limit_mb == null ? 100  : waf_configuration.value.file_upload_limit_mb
      request_body_check = waf_configuration.value.request_body_check == null ? true : waf_configuration.value.request_body_check
      max_request_body_size_kb = waf_configuration.value.max_request_body_size_kb == null ? 128 : waf_configuration.value.max_request_body_size_kb

      dynamic "exclusion" {
        for_each = waf_configuration.value.exclusion
        content {
        match_variable = exclusion.value.match_variable
        selector_match_operator = exclusion.value.selector_match_operator
        selector = exclusion.value.selector          
        }
      }    
      }
    }

    dynamic "redirect_configuration" {
      for_each = each.value.redirect_configuration
      content {
      name = redirect_configuration.value.name
      redirect_type = redirect_configuration.value.redirect_type
      target_listener_name = redirect_configuration.value.target_url == null ?  redirect_configuration.value.target_listener_name : null
      target_url = redirect_configuration.value.target_listener_name == null ?  redirect_configuration.value.target_url : null
      include_path = redirect_configuration.value.include_path == null ? false : redirect_configuration.value.include_path
      include_query_string = redirect_configuration.value.include_query_string == null ? false : redirect_configuration.value.include_query_string        
      }

    }

    autoscale_configuration {
      min_capacity = each.value.autoscale_configuration.min_capacity
      max_capacity = each.value.autoscale_configuration.max_capacity
    }

    dynamic "rewrite_rule_set" {
      for_each = each.value.rewrite_rule_set
      content {
      name = rewrite_rule_set.value.name
    dynamic "rewrite_rule" {
      for_each = rewrite_rule_set.value.rewrite_rule
      content {
        name = rewrite_rule.value.name
        rule_sequence = rewrite_rule.value.rule_sequence
        dynamic "condition" {
          for_each = rewrite_rule.value.condition
          content {
            variable = condition.value.variable
            pattern = condition.value.pattern
            ignore_case = condition.value.ignore_case
            negate = condition.value.negate            
          }
        }

        dynamic "request_header_configuration" {
          for_each = rewrite_rule.value.request_header_configuration
          content {
          header_name = request_header_configuration.value.header_name
          header_value = request_header_configuration.value.header_value            
          }
        }

        dynamic "response_header_configuration" {
          for_each = rewrite_rule.value.response_header_configuration
          content {
          header_name = response_header_configuration.value.header_name
          header_value = response_header_configuration.value.header_value            
          }

        }

        dynamic "url" {
        for_each = rewrite_rule.value.url
          content {
          path = url.value.path
          query_string = url.value.query_string
          components = url.value.components
          reroute = url.value.reroute            
          }

        }        
      }
      }       
      }

    }
}