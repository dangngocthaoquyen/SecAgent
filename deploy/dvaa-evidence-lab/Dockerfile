FROM dvaa-deepseek:local
COPY instrument.mjs /tmp/secagent-instrument.mjs
RUN node /tmp/secagent-instrument.mjs /app/src/index.js
ENV SECAGENT_LAB_EVIDENCE_DIR=/app/receipts
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s CMD node -e "require('net').connect(7010,'127.0.0.1').on('connect',function(){this.end();process.exit(0)}).on('error',function(){process.exit(1)})"
ENTRYPOINT []
CMD ["node", "src/index.js", "--mcp", "--only", "toolbot", "--offline"]
