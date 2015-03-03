# parse plugin versions from calls to updates.drupal.org
# inspired by Scott Campbell's wordpress plugin parser

@load base/frameworks/software

module DrupalParse;

export {
	# define enums for logging core or plugin versions
	redef enum Software::Type += {
		HTTP::DRUPAL_CORE,
		HTTP::DRUPAL_PLUGIN,
	};

	# make this a set to future proof. Maybe drupal changes to use
	# multiple URIs at some point
	const drupal_url: set[string] { "updates.drupal.org" } &redef;

}

# we hook http_message_done to get all our values
event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
	{
	# test to ensure this is a request we want
	if ( c$http$host in drupal_url && c$http$method == "GET" && /^\/release-history\// in c$http$uri && is_orig )
		{
		# example URI (this is the drupal core version)
		# /release-history/drupal/7.x?site_key=Vlwh7cLd2GRZWs2blCucKhcii33elvj4f1CS1zuve_g&version=7.34&list=block%2Cblog%2Ccolor%2Ccomment%2Ccontextual%2Cdashboard%2Cdblog%2Cfield%2Cfield_sql_storage%2Cfield_ui%2Cfile%2Cfilter%2Chelp%2Cimage%2Clist%2Cmenu%2Cnode%2Cnumber%2Coptions%2Coverlay%2Cpath%2Crdf%2Csearch%2Cshortcut%2Cstatistics%2Csystem%2Ctaxonomy%2Ctext%2Ctoolbar%2Cupdate%2Cuser%2Cbartik%2Cseven
		# split URI on pipe, ampersand and question to get plugin name and versions
		local uri_parts = split_string(c$http$uri, /\/|\&|\?/);
		# get our module or drupal core name
		local mod_name = uri_parts[2];
		# split on equal and hyphen to get our version number
		local mod_ver = split_string(uri_parts[5], /\=/);
		# a separator we use when making a fake version later
		local sep = "-";
		# drupal core version requires split on different position in array
		if ( mod_name == "drupal" )
			{
			# build fake version for unparsed_version in software framework
			# this may be poor form, since it isn't the actual unparsed_version
			local core_string = string_cat(mod_name, sep, mod_ver[1]);
			# get version parts, then convert 'em to counts
			local core_ver_string = split_string(mod_ver[1], /\./);
			local core_maj = to_count(core_ver_string[0]);
			local core_min = to_count(core_ver_string[1]);
			Software::found(c$id, [$name=mod_name, $version=[$major=core_maj, $minor=core_min], $unparsed_version=core_string, $host=c$id$orig_h, $software_type=HTTP::DRUPAL_CORE]);
			}
		# otherwise, assume we have a plugin version
		else
			{
			# build fake version for unparsed_version in software framework
			# this may be poor form, since it isn't the actual unparsed_version
			local plugin_string = string_cat(mod_name, sep, mod_ver[1]);
			# get version parts, then convert 'em to counts
			local plug_ver_string = split_string(mod_ver[1], /\.|\-/);
			local plug_ver_maj = to_count(plug_ver_string[2]);
			local plug_ver_min = to_count(plug_ver_string[3]);
			if ( |plug_ver_string| == 5 )
				{
				Software::found(c$id, [$name=mod_name, $version=[$major=plug_ver_maj, $minor=plug_ver_min, $addl=plug_ver_string[4]], $unparsed_version=plugin_string, $host=c$id$orig_h, $software_type=HTTP::DRUPAL_PLUGIN]);
				}
			else
				{
				Software::found(c$id, [$name=mod_name, $version=[$major=plug_ver_maj, $minor=plug_ver_min], $unparsed_version=plugin_string, $host=c$id$orig_h, $software_type=HTTP::DRUPAL_PLUGIN]);
				}
			}
		}
	}
