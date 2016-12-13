var gulp = require('gulp'),
    concat = require('gulp-concat'),
    uglify = require('gulp-uglify'),
    rename = require('gulp-rename'),
    ngAnnotate = require('gulp-ng-annotate'),
    inject = require('gulp-inject-string')

gulp.task('build', function() {
  gulp.src('src/**/*.js')
    .pipe(concat('angular-warden-oauth-client.js'))
    .pipe(inject.wrap('(function() {\n\n\n', '\n}());'))
    .pipe(ngAnnotate())
    .pipe(gulp.dest('./dist/'))
    .pipe(uglify())
    .pipe(rename('angular-warden-oauth-client.min.js'))
    .pipe(gulp.dest('./dist'))
});

gulp.task('default', ['build']);
