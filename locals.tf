
locals {  
    application_gateway = {for application_gateway in var.application_gateway_list : application_gateway.name => application_gateway}
}