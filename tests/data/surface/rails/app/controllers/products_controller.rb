class ProductsController < ApplicationController
  skip_before_action :authenticate_user!, only: [:index, :show, :search]

  def index
    @products = Product.all
  end

  def show
    @product = Product.find(params[:id])
  end

  def search
    @products = Product.where("name LIKE '%#{params[:q]}%'")
  end

  def create
    @product = Product.create(product_params)
  end

  def publish
    system("publish-tool #{params[:id]} #{params[:channel]}")
  end

  private

  def product_params
    params.require(:product).permit(:name, :price)
  end
end
