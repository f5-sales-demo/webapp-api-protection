# CSD matcher normalization. The exclude_list / insertion_rules.rules / insertion_rules.exclude_list
# entries all share one matcher shape (domain any/exact/regex/suffix + path exact/prefix/regex). The
# domain/path mode->field resolution is written ONCE here (the map comprehension) and applied to all
# three lists, so main.tf's dynamic blocks just reference the resolved fields.
locals {
  _csd_matcher_lists = {
    exclude_list           = var.csd.exclude_list
    insertion_rules        = try(var.csd.insertion_rules.rules, [])
    insertion_exclude_list = try(var.csd.insertion_rules.exclude_list, [])
  }

  _csd_normalized = {
    for key, lst in local._csd_matcher_lists : key => [
      for e in lst : {
        name          = e.name
        description   = e.description
        any_domain    = e.domain_mode == "any"
        domain_exact  = e.domain_mode == "exact" ? e.domain_value : null
        domain_regex  = e.domain_mode == "regex" ? e.domain_value : null
        domain_suffix = e.domain_mode == "suffix" ? e.domain_value : null
        path_exact    = e.path_mode == "exact" ? e.path_value : null
        path_prefix   = e.path_mode == "prefix" ? e.path_value : null
        path_regex    = e.path_mode == "regex" ? e.path_value : null
      }
    ]
  }

  csd_exclude_list           = local._csd_normalized.exclude_list
  csd_insertion_rules        = local._csd_normalized.insertion_rules
  csd_insertion_exclude_list = local._csd_normalized.insertion_exclude_list
}
