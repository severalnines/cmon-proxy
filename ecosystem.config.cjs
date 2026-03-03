module.exports = {
  apps: [
    {
      name: "cmon-proxy",
      script: "go",
      args: "run -tags dev .",
      watch: false,
      autorestart: false,
    },
  ],
};
