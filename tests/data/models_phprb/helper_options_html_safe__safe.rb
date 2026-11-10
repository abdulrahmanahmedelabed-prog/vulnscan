# expect-none: DF013
module SettingsHelper
  # `options` of a view helper is set by the template author, not by the request
  def setting_label(setting, options = {})
    label = options[:label] || setting.to_s.humanize
    content_tag(:label, label).html_safe
  end
end
