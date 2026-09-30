require("esbuild").buildSync({
  entryPoints: [require("node:path").join(__dirname, "App.js")],
  bundle: true,
  minify: true,
  sourcemap: true,
  outfile: require("node:path").join(__dirname, "dist/app.js"),
  loader: { ".js": "jsx" },
  target: ["es2020"],
  format: "iife",
});
