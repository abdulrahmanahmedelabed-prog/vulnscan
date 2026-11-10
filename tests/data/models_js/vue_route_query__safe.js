// expect-none: DF013
export default {
  mounted() {
    this.$refs.box.textContent = this.$route.query.msg;
  },
};
