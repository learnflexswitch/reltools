# Pull base image.
FROM snapos/flex:auto1

ADD libip4tc.so.0 /usr/local/libip4tc.so.0
ADD asicdConf.json /usr/local/asicdConf.json
ADD gen_image.sh /usr/local/bin/gen_image.sh
ADD flex.deb /usr/local/flex.deb
RUN chmod +x /usr/local/bin/gen_image.sh

CMD sh /usr/local/bin/gen_image.sh
