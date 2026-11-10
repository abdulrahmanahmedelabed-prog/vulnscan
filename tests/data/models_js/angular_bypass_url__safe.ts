// expect-none: DF013
export class LinkComponent {
  constructor(private route: ActivatedRoute, private sanitizer: DomSanitizer) {}
  link() {
    return this.sanitizer.bypassSecurityTrustUrl('https://example.com/help');
  }
}
