// expect: DF013
export default {
  mounted() {
    this.$refs.box.innerHTML = this.$route.query.msg;
  },
};
