FROM node:24-alpine AS builder

RUN apk add --no-cache python3 make g++ linux-headers

WORKDIR /pkg

COPY package.json binding.gyp ./
COPY src/ src/

RUN npm install --ignore-scripts
RUN npx prebuildify --napi --strip

# Prebuilds are now in /pkg/prebuilds/

FROM scratch
COPY --from=builder /pkg/prebuilds /prebuilds
