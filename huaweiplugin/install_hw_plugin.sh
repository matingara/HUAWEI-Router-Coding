cd cfgparser
cp * /usr/share/fa/bin/.
cd ../logparser
cp huawei_parser.pm /usr/share/fa/data/syslog_processor/parsers/.
cp huawei_parser_exclude.txt /usr/share/fa/data/syslog_processor/.
cp ProcessLogs.pl /usr/share/fa/data/syslog_processor/.
cd ../brand
mkdir /usr/share/fa/data/plugins/huawei
cp brand_config.xml /usr/share/fa/data/plugins/huawei/.
cp huawei.16.png /usr/share/fa/data/plugins/huawei/.
cp huawei.35.png /usr/share/fa/data/plugins/huawei/.
cp huawei.45.png /usr/share/fa/data/plugins/huawei/.
cp huawei.150.png /usr/share/fa/data/plugins/huawei/.
cp orig_rules_info.huawei /usr/share/fa/data/.

fa_install_plugin /usr/share/fa/data/plugins/huawei/brand_config.xml




