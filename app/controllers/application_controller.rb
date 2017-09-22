class ApplicationController < ActionController::Base
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :exception
  before_action :authenticate_user

  def authenticate_user
    client_id = ENV['client_id']
    client_secret = ENV['client_secret']

private
  def logged_in?
    !!session[:token]
  end

end
