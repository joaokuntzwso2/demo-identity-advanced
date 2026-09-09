FROM node:22-alpine AS build
WORKDIR /app
COPY package.json .
RUN npm install
COPY . .
RUN npm run build

FROM nginx:1.29-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
# MYAPPS_FINAL_IMAGE_COPY
# Keep the Microsoft/Ping-style launcher as an independent static surface.
# Copy it directly into the final nginx image; do not rely on Vite publicDir.
COPY public/myapps /usr/share/nginx/html/myapps
# MYAPPS_NGINX_ROUTE_FIX
RUN set -eux;     conf="/etc/nginx/conf.d/default.conf";     test -f "$conf";     grep -q 'location /' "$conf";     awk '       BEGIN { inserted = 0 }       !inserted && $0 ~ /^[[:space:]]*location[[:space:]]+\/[[:space:]]*\{/ {         print "    location = /myapps {";         print "        return 302 /myapps/;";         print "    }";         print "";         print "    location = /myapps/ {";         print "        try_files /myapps/index.html =404;";         print "    }";         print "";         print "    location ^~ /myapps/ {";         print "        try_files $uri =404;";         print "    }";         print "";         inserted = 1;       }       { print }       END { if (!inserted) exit 42 }     ' "$conf" > /tmp/default.conf;     mv /tmp/default.conf "$conf";     nginx -t
EXPOSE 80
