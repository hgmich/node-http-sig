module.exports = {
  'src/**/*.ts': [() => 'npm run typecheck', 'prettier -c'],
  './**/*.json': ['prettier -c'],
}
